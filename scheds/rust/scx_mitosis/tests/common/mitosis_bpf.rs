use anyhow::{Result, bail};
use libbpf_rs::{MapCore as _, MapFlags, MapHandle, query::MapInfoIter};

#[path = "../../src/bpf_intf.rs"]
pub mod bpf_intf;

pub fn cpu_contexts() -> Result<Vec<bpf_intf::cpu_ctx>> {
    let info = MapInfoIter::default()
        .find(|info| info.name.to_str() == Some("cpu_ctxs"))
        .ok_or_else(|| anyhow::anyhow!("Mitosis CPU context map is missing"))?;
    let map = MapHandle::from_map_id(info.id)?;
    let values = map
        .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)?
        .ok_or_else(|| anyhow::anyhow!("Mitosis CPU contexts are missing"))?;
    values
        .into_iter()
        .enumerate()
        .map(|(cpu, value)| {
            if value.len() < std::mem::size_of::<bpf_intf::cpu_ctx>() {
                bail!("CPU {cpu} context is too small: {} bytes", value.len());
            }
            // The generated C layout contains only integer fields. Per-CPU map
            // values need not meet the Rust struct's alignment.
            Ok(unsafe { std::ptr::read_unaligned(value.as_ptr().cast::<bpf_intf::cpu_ctx>()) })
        })
        .collect()
}

pub fn assert_cpu_llcs(expected: &[u32]) -> Result<()> {
    let values = cpu_contexts()?;
    for (cpu, &llc) in expected.iter().enumerate() {
        let actual = values
            .get(cpu)
            .ok_or_else(|| anyhow::anyhow!("CPU {cpu} context is missing"))?
            .llc;
        if actual != llc {
            eprintln!("CPU {cpu} uses LLC {actual}, expected {llc}");
            bail!("CPU {cpu} uses LLC {actual}, expected {llc}");
        }
    }
    Ok(())
}
