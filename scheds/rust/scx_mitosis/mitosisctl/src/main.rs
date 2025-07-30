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
use std::mem::MaybeUninit;

pub const LONG_HELP: &str = "mitosisctl is a small helper for the scx_mitosis\
scheduler.\n\n\
Commands:\n\
  list                       list available BPF map names\n\
  get <MAP>                  display current map contents\n\
  set <MAP>                  load map from host topology\n\
  topology                   display CPU to L3 mappings and vice versa\n";

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

fn set_entry(skel: &mut BpfSkel, map: &str) -> Result<()> {
    match map {
        "cpu_to_l3" => {
            let topo = Topology::new()?;
            for cpu in 0..*scx_utils::NR_CPUS_POSSIBLE {
                let key = (cpu as u32).to_ne_bytes();
                let l3 = topo.all_cpus.get(&cpu).map(|c| c.l3_id as u32).unwrap_or(0);
                let val = l3.to_ne_bytes();
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
        Commands::Set { map } => set_entry(&mut skel, &map)?,
        Commands::Topology => print_topology()?,
    }
    Ok(())
}
