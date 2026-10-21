#[path = "../src/explore_probe_math.rs"]
#[allow(dead_code)]
mod math;

use std::io::Write;
use std::process::{Command, Stdio};

use math::Histogram;

// Compile the production recorder with the actual SCX log2 helpers. The native
// harness supplies no BPF maps and preserves the recorder's atomic operations.
fn c_definition<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source.find(marker).unwrap();
    let body = start + source[start..].find('{').unwrap();
    let mut depth = 0;
    for (offset, byte) in source.as_bytes()[body..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..=body + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated C definition {marker}");
}

fn native_histograms(samples: &[u64]) -> Vec<Histogram> {
    let observer = include_str!("../src/bpf/explore.bpf.c");
    let common = include_str!("../../../scheds/include/scx/common.bpf.h");
    let bucket_define = observer
        .lines()
        .find(|line| line.starts_with("#define EXPLORE_BUCKETS "))
        .unwrap();
    let source = format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n\
         typedef uint32_t u32; typedef uint64_t u64;\n\
         #undef __always_inline\n#define __always_inline inline __attribute__((always_inline))\n\
         #define READ_ONCE(value) (*(volatile __typeof__(value) *)&(value))\n\
         {bucket_define}\n{};\n{}\n{}\n{}\n\
         int main(int argc, char **argv) {{\n\
           for (int sample = 1; sample < argc; sample++) {{\n\
             struct explore_histogram histogram = {{0}};\n\
             record_histogram(&histogram, strtoull(argv[sample], NULL, 10));\n\
             printf(\"%llu %llu %llu\", (unsigned long long)histogram.total_ns,\n\
               (unsigned long long)histogram.max_ns, (unsigned long long)histogram.max_update_failures);\n\
             for (u32 bucket = 0; bucket < EXPLORE_BUCKETS; bucket++)\n\
               printf(\" %llu\", (unsigned long long)histogram.buckets[bucket]);\n\
             putchar('\\n');\n\
           }}\nreturn 0;\n}}\n",
        c_definition(observer, "struct explore_histogram {"),
        c_definition(common, "static inline u32 log2_u32("),
        c_definition(common, "static inline u32 log2_u64("),
        c_definition(observer, "static __always_inline void record_histogram("),
    );
    run_native(&source, samples.iter().map(u64::to_string))
        .lines()
        .map(|line| {
            let values = line
                .split_whitespace()
                .map(|value| value.parse::<u64>().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(values.len(), 67);
            Histogram {
                total_ns: values[0],
                max_ns: values[1],
                max_update_failures: values[2],
                buckets: values[3..].try_into().unwrap(),
                ..Histogram::default()
            }
        })
        .collect()
}

fn run_native(source: &str, arguments: impl IntoIterator<Item = String>) -> String {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let binary = std::env::temp_dir().join(format!(
        "mitosis-explore-native-{}-{unique}",
        std::process::id()
    ));
    let mut compiler = Command::new("cc")
        .args([
            "-O2",
            "-Wall",
            "-Werror",
            "-Wno-unknown-pragmas",
            "-x",
            "c",
            "-",
            "-o",
        ])
        .arg(&binary)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    let compiled = compiler.wait_with_output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let output = Command::new(&binary).args(arguments).output().unwrap();
    std::fs::remove_file(binary).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn native_recorder_uses_floor_log2_nanosecond_buckets() {
    let samples = [
        0,
        1,
        2,
        3,
        1023,
        1024,
        2047,
        2048,
        1 << 31,
        (1 << 32) - 1,
        1 << 32,
        (1 << 63) - 1,
        1 << 63,
        u64::MAX,
    ];
    let expected_buckets = [0, 0, 1, 1, 9, 10, 10, 11, 31, 31, 32, 62, 63, 63];
    for ((ns, expected), histogram) in samples
        .into_iter()
        .zip(expected_buckets)
        .zip(native_histograms(&samples))
    {
        assert_eq!(histogram.samples(), 1);
        assert_eq!(
            histogram.buckets[expected], 1,
            "recording {ns}ns into bucket {expected}"
        );
    }
}

#[test]
fn recorded_maximum_and_live_bucket_bound_agree_for_measured_latency() {
    for (mut histogram, maximum) in native_histograms(&[1024, 1500])
        .into_iter()
        .zip([1.024, 1.5])
    {
        assert_eq!(histogram.exact_max_us(), Some(maximum));
        assert_eq!(histogram.mean_us(), Some(maximum));
        histogram.max_known = false;
        assert_eq!(histogram.quantile_us(50.0), Some(2.047));
        assert_eq!(histogram.quantile_us(95.0), Some(2.047));
        assert_eq!(histogram.quantile_us(99.0), Some(2.047));
    }
}

struct MaskResult {
    callbacks: u64,
    reads: u64,
    failures: u64,
    targets: Vec<u32>,
}

fn native_ipi_mask(cpu_limit: u32, words: &[u64], failed_word: Option<u32>) -> MaskResult {
    let observer = include_str!("../src/bpf/explore.bpf.c");
    let common = include_str!("../../../scheds/include/scx/common.bpf.h");
    let max_cpus_define = observer
        .lines()
        .find(|line| line.starts_with("#define EXPLORE_MAX_CPUS "))
        .unwrap();
    let source = format!(
        r#"
        #include <assert.h>
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        typedef uint32_t u32; typedef uint64_t u64;
        #define SEC(section)
        #define BPF_PROG(name, ...) name(__VA_ARGS__)
        {max_cpus_define}
        struct cpumask {{ u64 bits[EXPLORE_MAX_CPUS / 64]; }};
        {};
        {};
        static int explore_config;
        static struct explore_config_value test_config;
        static struct explore_health test_health;
        static struct cpumask test_mask;
        static u64 callbacks, reads, targets[EXPLORE_MAX_CPUS];
        static int failed_word;
        static struct explore_health *health(void) {{ return &test_health; }}
        static void *bpf_map_lookup_elem(const void *map, const void *key) {{
            assert(map == &explore_config && *(const u32 *)key == 0);
            return &test_config;
        }}
        static int bpf_probe_read_kernel(void *destination, u32 size, const void *source) {{
            size_t word = (const u64 *)source - test_mask.bits;
            assert(word < EXPLORE_MAX_CPUS / 64 && size == sizeof(u64));
            reads++;
            if ((int)word == failed_word) return -1;
            memcpy(destination, source, size);
            return 0;
        }}
        static void record_ipi_target(u32 cpu) {{
            assert(cpu < EXPLORE_MAX_CPUS);
            targets[cpu]++;
        }}
        static long bpf_loop(u32 limit, long (*callback)(u32, void *), void *context, u64 flags) {{
            assert(flags == 0);
            for (u32 index = 0; index < limit; index++) {{
                callbacks++;
                if (callback(index, context)) return index + 1;
            }}
            return limit;
        }}
        {}
        {}
        {};
        {}
        {}
        int main(int argc, char **argv) {{
            test_config.cpu_limit = strtoul(argv[1], NULL, 10);
            failed_word = atoi(argv[2]);
            for (int word = 3; word < argc; word++)
                test_mask.bits[word - 3] = strtoull(argv[word], NULL, 10);
            ex_ipi_send_cpumask(&test_mask, NULL, NULL);
            printf("%llu %llu %llu", (unsigned long long)callbacks, (unsigned long long)reads,
                (unsigned long long)test_health.ipi_mask_read_failures);
            for (u32 cpu = 0; cpu < EXPLORE_MAX_CPUS; cpu++)
                for (u64 count = 0; count < targets[cpu]; count++) printf(" %u", cpu);
            putchar('\n');
            return 0;
        }}
        "#,
        c_definition(observer, "struct explore_config_value {"),
        c_definition(observer, "struct explore_health {"),
        c_definition(common, "static inline u32 log2_u32("),
        c_definition(common, "static inline u32 log2_u64("),
        c_definition(observer, "struct explore_ipi_loop_context {"),
        observer
            .match_indices("static long explore_ipi_loop_")
            .map(|(offset, _)| c_definition(&observer[offset..], "static long explore_ipi_loop_"))
            .collect::<Vec<_>>()
            .join("\n"),
        c_definition(observer, "int BPF_PROG(ex_ipi_send_cpumask,"),
    );
    let mut arguments = vec![
        cpu_limit.to_string(),
        failed_word
            .map(|word| word.to_string())
            .unwrap_or_else(|| "-1".into()),
    ];
    arguments.extend(words.iter().map(u64::to_string));
    let output = run_native(&source, arguments);
    let values = output
        .split_whitespace()
        .map(|value| value.parse::<u64>().unwrap())
        .collect::<Vec<_>>();
    MaskResult {
        callbacks: values[0],
        reads: values[1],
        failures: values[2],
        targets: values[3..].iter().map(|cpu| *cpu as u32).collect(),
    }
}

#[test]
fn ipi_mask_preserves_sparse_cpu_ids_and_excludes_bits_above_the_bound() {
    let observed = native_ipi_mask(
        316,
        &[
            1 | 1 << 63,
            1 << 16 | 1 << 31,
            0,
            0,
            1 << 59 | 1 << 60 | 1 << 63,
        ],
        None,
    );
    assert_eq!(observed.targets, [0, 63, 80, 95, 315]);
    assert_eq!(observed.reads, 5);
    assert_eq!(observed.failures, 0);
    let observed = native_ipi_mask(65, &[u64::MAX, u64::MAX], None);
    assert_eq!(observed.targets, (0..=64).collect::<Vec<_>>());
}

#[test]
fn ipi_mask_read_failure_stops_before_unknown_later_targets() {
    let observed = native_ipi_mask(316, &[1, 1, 1, 1, 1], Some(1));
    assert_eq!(observed.targets, [0]);
    assert_eq!(observed.reads, 2);
    assert_eq!(observed.failures, 1);
}

#[test]
fn empty_ipi_mask_visits_five_words_instead_of_316_cpu_callbacks() {
    let observed = native_ipi_mask(316, &[0; 5], None);
    assert!(observed.targets.is_empty());
    assert_eq!(observed.callbacks, 5);
    assert_eq!(observed.reads, 5);
    assert_eq!(observed.failures, 0);
}
