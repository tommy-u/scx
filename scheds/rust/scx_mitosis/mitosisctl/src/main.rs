mod bpf_intf;
mod bpf_skel;
mod cli;

use anyhow::Result;
use bpf_skel::{BpfSkel, BpfSkelBuilder};
use clap::Parser;
use cli::{Cli, Commands};
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::{MapCore, MapFlags};
use scx_utils::scx_ops_open;
use scx_utils::Topology;
use std::io::{self, BufRead, BufReader};
use std::mem::MaybeUninit;
use std::path::Path;

pub const LONG_HELP: &str = "mitosisctl is a small helper for the scx_mitosis\
scheduler.\n\n";// ;

fn print_topology() -> Result<()> {
    let topo = Topology::new()?;
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

fn open_skel() -> Result<BpfSkel<'static>> {
    let open_obj = Box::leak(Box::new(MaybeUninit::uninit()));
    let mut builder = BpfSkelBuilder::default();
    builder.obj_builder.debug(false);
    let skel = scx_ops_open!(builder, open_obj, mitosis)?;
    let skel = skel.load()?;
    Ok(skel)
}

fn list_maps() {
    println!("Available BPF maps:");
    let names = ["cpu_to_l3"];
    for name in names {
        println!("{name}");
    }
}

fn parse_cpu_l3_map<R: BufRead>(reader: R) -> Result<Vec<(usize, usize)>> {
    let mut pairs = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
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

fn get_entry(skel: &BpfSkel, map: &str) -> Result<()> {
    match map {
        "cpu_to_l3" => {
            for cpu in 0..*scx_utils::NR_CPUS_POSSIBLE {
                let key = (cpu as u32).to_ne_bytes();
                let val = skel
                    .maps
                    .cpu_to_l3
                    .lookup(&key, MapFlags::ANY)?
                    .map(|v| u32::from_ne_bytes(v.try_into().unwrap()))
                    .unwrap_or(0);
                println!("cpu {cpu} -> {val}");
            }
        }
        _ => {
            anyhow::bail!("unknown map {map}");
        }
    }
    Ok(())
}

fn set_entry(skel: &mut BpfSkel, map: &str, file: Option<String>) -> Result<()> {
    match map {
        "cpu_to_l3" => {
            let map_entries = if let Some(path) = file {
                println!("loading from {path}");
                read_cpu_l3_map(&path)?
            } else {
                println!("loading from host topology");
                let topo = Topology::new()?;
                (0..*scx_utils::NR_CPUS_POSSIBLE)
                    .map(|cpu| (cpu, topo.all_cpus.get(&cpu).map(|c| c.l3_id).unwrap_or(0)))
                    .collect()
            };
            for (cpu, l3) in map_entries {
                let key = (cpu as u32).to_ne_bytes();
                let val = (l3 as u32).to_ne_bytes();
                skel.maps.cpu_to_l3.update(&key, &val, MapFlags::ANY)?;
            }
        }
        _ => {
            anyhow::bail!("unknown map {map}");
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut skel = open_skel()?;

    match cli.command {
        Commands::List => list_maps(),
        Commands::Get { map } => get_entry(&skel, &map)?,
        Commands::Set { map, file } => set_entry(&mut skel, &map, file)?,
        Commands::Topology => print_topology()?,
    }
    Ok(())
}
