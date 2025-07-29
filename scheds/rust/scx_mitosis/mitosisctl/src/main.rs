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
use std::mem::MaybeUninit;
use scx_utils::Topology;

pub const LONG_HELP: &str = "mitosisctl is a small helper for the scx_mitosis\
scheduler.\n\n\
Commands:\n\
  list                       list available BPF map names\n\
  get <MAP> <KEY>            fetch the value stored at KEY in MAP\n\
  set <MAP> <KEY> <VALUE>    set MAP[KEY] to VALUE\n\
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
    let names = [
        "cgrp_ctxs",
        "task_ctxs",
        "cpu_ctxs",
        "cell_cpumasks",
        "percpu_critical_sections",
        "cgrp_init_percpu_cpumask",
    ];
    for name in names {
        println!("{name}");
    }
}

fn get_entry(skel: &BpfSkel, map: &str, key: u32) -> Result<()> {
    let key_bytes = key.to_ne_bytes();
    let value = match map {
        "cgrp_ctxs" => skel
            .maps
            .cgrp_ctxs
            .lookup(&key_bytes, MapFlags::ANY)?
            .map(|v| u32::from_ne_bytes(v.try_into().unwrap())),
        "task_ctxs" => skel
            .maps
            .task_ctxs
            .lookup(&key_bytes, MapFlags::ANY)?
            .map(|v| u32::from_ne_bytes(v.try_into().unwrap())),
        "cpu_ctxs" => skel
            .maps
            .cpu_ctxs
            .lookup(&key_bytes, MapFlags::ANY)?
            .map(|v| u32::from_ne_bytes(v.try_into().unwrap())),
        "cell_cpumasks" => skel
            .maps
            .cell_cpumasks
            .lookup(&key_bytes, MapFlags::ANY)?
            .map(|v| u32::from_ne_bytes(v.try_into().unwrap())),
        "percpu_critical_sections" => skel
            .maps
            .percpu_critical_sections
            .lookup(&key_bytes, MapFlags::ANY)?
            .map(|v| u32::from_ne_bytes(v.try_into().unwrap())),
        "cgrp_init_percpu_cpumask" => skel
            .maps
            .cgrp_init_percpu_cpumask
            .lookup(&key_bytes, MapFlags::ANY)?
            .map(|v| u32::from_ne_bytes(v.try_into().unwrap())),
        _ => {
            anyhow::bail!("unknown map {map}");
        }
    };

    if let Some(val) = value {
        println!("{val}");
    }
    Ok(())
}

fn set_entry(skel: &mut BpfSkel, map: &str, key: u32, value: u32) -> Result<()> {
    let key_bytes = key.to_ne_bytes();
    let val_bytes = value.to_ne_bytes();
    match map {
        "cgrp_ctxs" => skel
            .maps
            .cgrp_ctxs
            .update(&key_bytes, &val_bytes, MapFlags::ANY)?,
        "task_ctxs" => skel
            .maps
            .task_ctxs
            .update(&key_bytes, &val_bytes, MapFlags::ANY)?,
        "cpu_ctxs" => skel
            .maps
            .cpu_ctxs
            .update(&key_bytes, &val_bytes, MapFlags::ANY)?,
        "cell_cpumasks" => skel
            .maps
            .cell_cpumasks
            .update(&key_bytes, &val_bytes, MapFlags::ANY)?,
        "percpu_critical_sections" => {
            skel.maps
                .percpu_critical_sections
                .update(&key_bytes, &val_bytes, MapFlags::ANY)?
        }
        "cgrp_init_percpu_cpumask" => {
            skel.maps
                .cgrp_init_percpu_cpumask
                .update(&key_bytes, &val_bytes, MapFlags::ANY)?
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
        Commands::Get { map, key } => get_entry(&skel, &map, key)?,
        Commands::Set { map, key, value } => set_entry(&mut skel, &map, key, value)?,
        Commands::Topology => print_topology()?,
    }
    Ok(())
}
