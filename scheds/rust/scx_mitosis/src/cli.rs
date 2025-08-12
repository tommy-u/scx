use clap::{Parser, Subcommand};
use anyhow::{bail, Context, Result};
use colored::Colorize;
use rand::Rng;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader};
use std::mem::MaybeUninit;
use std::os::unix::io::AsFd;
use std::path::Path;
use std::process::Command;

use crate::bpf_skel::{BpfSkel, BpfSkelBuilder};
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::{MapCore, MapFlags, MapHandle, OpenMapMut};
use scx_utils::{scx_ops_open, Topology, Cpumask};

const CPUMASK_LONG_ENTRIES: usize = 128;

pub const LONG_HELP: &str = "mitosisctl is a small helper for the scx_mitosis scheduler.\n\n";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = LONG_HELP)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Splash screen
    Splash,
    /// List available BPF maps
    List,
    /// Get state of a map
    Get {
        /// Map name
        map: String,
    },
    /// Load map from topology or from file (if -f is specified)
    Set {
        /// Map name
        map: String,
        /// Optional topology file ("-" for stdin)
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
    /// Print processor topology
    Topology,
    /// Check if scx_mitosis is currently running
    Running,
}

/// Verify that `bpftool` exists on the system and is executable.
fn check_bpftool_available() -> Result<()> {
    let output = Command::new("bpftool").args(["--version"]).output()?;
    if !output.status.success() {
        bail!("bpftool command failed. Check if it's properly installed.");
    }
    Ok(())
}

/// Query bpftool for the ID of the BPF map with the given name.
fn find_map_id_by_name(map_name: &str) -> Result<u32> {
    let output = Command::new("bpftool")
        .args(["map", "show", "name", map_name, "--json"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("bpftool map show failed. Is scx_mitosis running? Try mitosisctl list: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        bail!("Map '{}' not found. Is scx_mitosis running? Try mitosisctl list", map_name);
    }

    // bpftool prints JSON like `{ "id": 123 }`; parse it to grab the numeric id
    let json: Value =
        serde_json::from_str(&stdout).context("Failed to parse bpftool JSON output")?;
    let id = json["id"]
        .as_u64()
        .context("Missing or invalid 'id' field in bpftool output")?;
    Ok(id as u32)
}

/// Reuse an already pinned map (created by the scheduler) for our skeleton map.
fn attach_to_existing_map(existing_map_name: &str, new_map: &mut OpenMapMut) -> Result<MapHandle> {
    check_bpftool_available()?;
    let map_id = find_map_id_by_name(existing_map_name)?;
    let map_handle = MapHandle::from_map_id(map_id)?;
    let borrowed_fd = map_handle.as_fd();
    // Point the skeleton's map at the existing kernel map by reusing its FD
    new_map.reuse_fd(borrowed_fd)?;
    Ok(map_handle)
}

/// Display CPU to L3 cache relationships discovered from the host topology.
fn print_topology() -> Result<()> {
    let topo = Topology::new()?;
    println!("Number L3 caches: {}", topo.all_llcs.len());
    println!("CPU -> L3 id:");
    for cpu in topo.all_cpus.values() {
        println!("cpu {} -> {}", cpu.id, cpu.l3_id);
    }
    println!("\nL3 id -> [cpus]:");
    let mut by_l3: std::collections::BTreeMap<usize, Vec<usize>> =
        std::collections::BTreeMap::new();
    for cpu in topo.all_cpus.values() {
        by_l3.entry(cpu.l3_id).or_default().push(cpu.id);
    }
    for (l3, mut cpus) in by_l3 {
        cpus.sort_unstable();
        println!("{l3} -> {:?}", cpus);
    }
    Ok(())
}

/// Open the BPF skeleton and attach its maps to the scheduler's maps.
fn open_skel() -> Result<(BpfSkel<'static>, HashMap<&'static str, MapHandle>)> {
    // Leak an uninitialized object so the skeleton lives for 'static lifetime
    let open_obj = Box::leak(Box::new(MaybeUninit::uninit()));
    let mut builder = BpfSkelBuilder::default();
    // Disable libbpf debug messages
    builder.obj_builder.debug(false);
    let mut skel = scx_ops_open!(builder, open_obj, mitosis)?;
    let mut handles = HashMap::new();
    // Bind our skeleton map to the one already created by the kernel scheduler
    let handle = attach_to_existing_map("cpu_to_l3", &mut skel.maps.cpu_to_l3)?;
    handles.insert("cpu_to_l3", handle);
    // Finalise and load the BPF object
    let skel = skel.load()?;
    // Return both the loaded skeleton and the handle keeping the map alive
    Ok((skel, handles))
}

/// Count how many BPF maps with the given name currently exist.
fn count_maps_by_name(map_name: &str) -> Result<usize> {
    let output = Command::new("bpftool")
        .args(["map", "show", "name", map_name, "--json"])
        .output()?;

    if !output.status.success() {
        return Ok(0);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(0);
    }

    let json: Value = serde_json::from_str(&stdout)?;
    // bpftool returns either a single object or an array depending on how many maps match
    if json.is_array() {
        Ok(json.as_array().unwrap().len())
    } else {
        Ok(1)
    }
}

/// Print all supported map names along with how many instances exist.
fn list_maps() {
    println!("Supported BPF Maps    Count");
    let names = ["cpu_to_l3", "l3_to_cpus"];
    for name in names {
        let count = count_maps_by_name(name).unwrap_or(0);
        if count == 1 {
            println!("{:<20} {}", name, count);
        } else {
            println!("{:<20} \x1b[31m{}\x1b[0m", name, count);
        }
    }
}

/// Parse lines of the form `cpu,l3` from the provided reader.
fn parse_cpu_l3_map<R: BufRead>(reader: R) -> Result<Vec<(usize, usize)>> {
    let mut pairs = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        // Ignore blank lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(',');
        let cpu = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing cpu"))?
            .trim()
            .parse::<usize>()?;
        let l3 = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing l3"))?
            .trim()
            .parse::<usize>()?;
        pairs.push((cpu, l3));
    }
    Ok(pairs)
}

/// Read CPU/L3 pairs either from a file or standard input.
fn read_cpu_l3_map(path: &str) -> Result<Vec<(usize, usize)>> {
    if path == "-" {
        println!("reading from stdin");
        let stdin = io::stdin();
        let reader = BufReader::new(stdin.lock());
        parse_cpu_l3_map(reader)
    } else {
        println!("reading from {path}");
        let file = std::fs::File::open(Path::new(path))?;
        let reader = BufReader::new(file);
        parse_cpu_l3_map(reader)
    }
}

/// Print the contents of the requested map.
fn get_entry(skel: &BpfSkel, map: &str) -> Result<()> {
    match map {
        "cpu_to_l3" => {
            // Iterate over all possible CPUs
            for cpu in 0..*scx_utils::NR_CPUS_POSSIBLE {
                let key = (cpu as u32).to_ne_bytes();
                let val = skel
                    .maps
                    .cpu_to_l3
                    // MapFlags::ANY avoids RCU semantics for simple lookups
                    .lookup(&key, MapFlags::ANY)?
                    .map(|v| u32::from_ne_bytes(v.try_into().unwrap()))
                    .unwrap_or(0);
                println!("cpu {cpu} -> {val}");
            }
        }
        "l3_to_cpus" => {
            // Get the number of L3 caches from the BPF rodata
            let nr_l3 = skel.maps.rodata_data.as_ref().unwrap().nr_l3;

            // Iterate over all L3 caches
            for l3 in 0..nr_l3 {
                let key = (l3 as u32).to_ne_bytes();
                let mask = if let Some(v) = skel
                    .maps
                    .l3_to_cpus
                    .lookup(&key, MapFlags::ANY)?
                {
                    let bytes = v.as_slice();
                    let mut longs = [0u64; CPUMASK_LONG_ENTRIES];
                    let mut i = 0;
                    while i < CPUMASK_LONG_ENTRIES && i * 8 + 8 <= bytes.len() {
                        longs[i] = u64::from_ne_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
                        i += 1;
                    }
                    Cpumask::from_vec(longs.to_vec())
                } else {
                    Cpumask::new()
                };
                println!("l3 {l3} -> {mask}");
            }
        }
        _ => {
            anyhow::bail!("unknown map {map}");
        }
    }
    Ok(())
}

/// Update map entries either from a file or from the host topology.
pub fn set_entry(skel: &mut BpfSkel, map: &str, file: Option<String>) -> Result<()> {
    match map {
        "cpu_to_l3" => {
            let map_entries = if let Some(path) = file {
                println!("loading from {path}");
                read_cpu_l3_map(&path)?
            } else {
                println!("loading from host topology");
                let topo = Topology::new()?;
                (0..*scx_utils::NR_CPUS_POSSIBLE)
                    // Use 0 if a CPU is missing from the topology
                    .map(|cpu| (cpu, topo.all_cpus.get(&cpu).map(|c| c.l3_id).unwrap_or(0)))
                    .collect()
            };
            for (cpu, l3) in map_entries {
                // Each CPU index is stored as a 32bit key mapping to its L3 id
                let key = (cpu as u32).to_ne_bytes();
                let val = (l3 as u32).to_ne_bytes();
                skel.maps.cpu_to_l3.update(&key, &val, MapFlags::ANY)?;
            }
        }
        "l3_to_cpus" => {
            if file.is_some() {
                anyhow::bail!("Loading l3_to_cpus from file is not supported yet");
            }

            println!("loading l3_to_cpus from host topology");
            let topo = Topology::new()?;

            // Group CPUs by L3 cache ID
            let mut l3_to_cpus: HashMap<usize, Vec<usize>> = HashMap::new();
            for cpu in topo.all_cpus.values() {
                l3_to_cpus.entry(cpu.l3_id).or_default().push(cpu.id);
            }

            // For each L3 cache, create a cpumask and populate the map
            for (l3_id, cpus) in l3_to_cpus {
                let key = (l3_id as u32).to_ne_bytes();

                // Create a cpumask structure that matches the BPF side
                let mut cpumask_longs = [0u64; CPUMASK_LONG_ENTRIES];

                // Set bits for each CPU in this L3 cache
                for cpu in cpus {
                    let long_idx = cpu / 64;
                    let bit_idx = cpu % 64;
                    if long_idx < CPUMASK_LONG_ENTRIES {
                        cpumask_longs[long_idx] |= 1u64 << bit_idx;
                    }
                }

                // Convert to bytes for the map update
                let mut value_bytes = Vec::new();
                for long_val in cpumask_longs {
                    value_bytes.extend_from_slice(&long_val.to_ne_bytes());
                }

                skel.maps.l3_to_cpus.update(&key, &value_bytes, MapFlags::ANY)
                    .context(format!("Failed to update l3_to_cpus map for L3 {}", l3_id))?;
            }
        }
        _ => {
            anyhow::bail!("unknown map {map}");
        }
    }
    Ok(())
}

const TITLE: &[&str] = &[
    "   ███╗   ███╗██╗████████╗ ██████╗ ███████╗██╗███████╗",
    "   ████╗ ████║██║╚══██╔══╝██╔═══██╗██╔════╝  ║██╔════╝",
    "   ██╔████╔██║██║   ██║   ██║   ██║███████╗██║███████╗",
    "   ██║╚██╔╝██║██║   ██║   ██║   ██║╚════██║██║╚════██║",
    "   ██║ ╚═╝ ██║██║   ██║   ╚██████╔╝███████║██║███████║",
    "   ╚═╝     ╚═╝╚═╝   ╚═╝    ╚═════╝ ╚══════╝╚═╝╚══════╝",
];

const CELLS: &[&str] = &[
    "          .---------.            .---------.          ",
    "       _ /           \\ _      _ /           \\ _       ",
    "      ( (    o   o    ) )~~~~( (    o   o    ) )      ",
    "       \\  \\    ^    /  /      \\  \\    ^    /  /       ",
    "        '. '._____.' .'        '. '._____.' .'        ",
    "          '-----------'          '-----------'         ",
];

/// Print the colourful ASCII-art splash.
pub fn print_splash() {
    let mut rng = rand::thread_rng();

    /* Banner — random colour per line */
    for line in TITLE.iter() {
        let r = rng.gen_range(100..=255);
        let g = rng.gen_range(100..=255);
        let b = rng.gen_range(100..=255);
        println!("{}", line.truecolor(r, g, b));
    }
    println!(); // spacer

    /* Cell art — random colors for left and right halves */
    for line in CELLS.iter() {
        let mid = line.len() / 2;
        let left  = &line[..mid];
        let right = &line[mid..];

        // Generate random colors for left and right sides
        let lr = rng.gen_range(100..=255);
        let lg = rng.gen_range(100..=255);
        let lb = rng.gen_range(100..=255);

        let rr = rng.gen_range(100..=255);
        let rg = rng.gen_range(100..=255);
        let rb = rng.gen_range(100..=255);

        print!("{}",  left.truecolor(lr, lg, lb));
        println!("{}", right.truecolor(rr, rg, rb));
    }
    }

/// Entry point for the CLI application.
pub fn run_cli() -> Result<()> {
    let cli = Cli::parse_from(std::env::args().skip(1));

    match cli.command {
        Commands::Splash => print_splash(),
        Commands::List => list_maps(),
        Commands::Get { map } => {
            // Keep the returned MapHandle alive while operating on the map
            let (skel, _map_handles) = open_skel()?;
            get_entry(&skel, &map)?;
        }
        Commands::Set { map, file } => {
            let (mut skel, _map_handles) = open_skel()?;
            set_entry(&mut skel, &map, file)?;
        }
        Commands::Topology => print_topology()?,
        Commands::Running => {
            println!("{}", is_scx_mitosis_running()?);
        }
    }
    Ok(())
}

/// Check if scx_mitosis is currently running by checking system files
fn is_scx_mitosis_running() -> Result<bool> {
    // Check if the sched_ext state file exists
    let state_path = "/sys/kernel/sched_ext/state";
    if !Path::new(state_path).exists() {
        return Ok(false);
    }

    // Read the state file to see if sched_ext is enabled
    let state = std::fs::read_to_string(state_path)
        .context("Failed to read sched_ext state")?;

    if state.trim() != "enabled" {
        return Ok(false);
    }

    // If enabled, check if the current scheduler is mitosis
    let opt_path = "/sys/kernel/sched_ext/root/ops";
    if !Path::new(opt_path).exists() {
        return Ok(false);
    }

    let opt = std::fs::read_to_string(opt_path)
        .context("Failed to read sched_ext opt")?;

    Ok(opt.trim() == "mitosis")
}
