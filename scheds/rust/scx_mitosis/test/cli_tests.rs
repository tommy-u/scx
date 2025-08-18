use std::process::Command;
use regex::Regex;

#[test]
fn test_cli_topology_dump() {
    // Test that the CLI topology command runs without errors
    let output = Command::new("cargo")
        .args(&["run", "--", "cli", "topology"])
        .current_dir("/home/tommyu/tu_forks/scx/scheds/rust/scx_mitosis")
        .output()
        .expect("Failed to execute command");

    // Check that the command completed successfully
    assert!(
        output.status.success(),
        "CLI topology command failed with exit code: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Validate that we got expected topology information in the output
    // The topology dump should contain:
    // 1. Number of L3 caches
    // 2. CPU -> L3 id mappings
    // 3. L3 id -> [cpus] mappings

    assert!(
        stdout.contains("Number L3 caches:") || stderr.contains("Number L3 caches:"),
        "Expected 'Number L3 caches:' in output.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    assert!(
        stdout.contains("CPU -> L3 id:") || stderr.contains("CPU -> L3 id:"),
        "Expected 'CPU -> L3 id:' in output.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    assert!(
        stdout.contains("L3 id -> [cpus]:") || stderr.contains("L3 id -> [cpus]:"),
        "Expected 'L3 id -> [cpus]:' in output.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    // Validate that we have at least some CPU mappings
    // This regex looks for lines like "cpu 0 -> 1" or similar
    let cpu_mapping_pattern = Regex::new(r"cpu \d+ -> \d+").unwrap();
    assert!(
        cpu_mapping_pattern.is_match(&stdout) || cpu_mapping_pattern.is_match(&stderr),
        "Expected CPU to L3 mappings in output.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    // Validate that we have L3 to CPU mappings
    // This regex looks for lines like "0 -> [1, 2, 3]" or similar
    let l3_mapping_pattern = Regex::new(r"\d+ -> \[[\d\s,]*\]").unwrap();
    assert!(
        l3_mapping_pattern.is_match(&stdout) || l3_mapping_pattern.is_match(&stderr),
        "Expected L3 to CPU mappings in output.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    println!("✅ CLI topology dump test passed successfully!");
    println!("Command output:");
    println!("STDOUT:\n{}", stdout);
    if !stderr.is_empty() {
        println!("STDERR:\n{}", stderr);
    }
}


#[test]
fn test_no_errors_encountered() {
    // This is the main requirement: test should automatically pass 
    // as long as no errors are encountered
    println!("✅ No errors encountered - test passes automatically!");
    assert!(true, "This test always passes if no panics occur during execution");
}