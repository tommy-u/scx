// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result};
use libbpf_rs::btf::{
    types::{Int, MemberAttr, Struct},
    Btf, BtfType, HasSize, TypeId,
};
use libbpf_rs::query::{ProgInfoIter, ProgInfoQueryOptions};
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};

/// Read the same cpu_ctx.cell ownership that Mitosis uses to rebuild cell masks.
/// The loaded object's BTF supplies the offset, so scheduler layout changes do
/// not turn statistics bytes into invented cell IDs. No map writes or probes.
pub struct CpuAllocationReader {
    map: MapHandle,
    cell_offset: usize,
}

impl CpuAllocationReader {
    pub fn open(program_id: u32) -> Result<Self> {
        let program =
            ProgInfoIter::with_query_opts(ProgInfoQueryOptions::default().include_map_ids(true))
                .find(|program| program.id == program_id)
                .context("Mitosis callback program is unavailable")?;
        let map = program
            .map_ids
            .iter()
            .filter_map(|id| MapHandle::from_map_id(*id).ok())
            .find(|map| map.name().to_str() == Some("cpu_ctxs"))
            .context("Mitosis cpu_ctxs map is unavailable")?;
        let info = map.info()?;
        ensure!(
            map.map_type() == MapType::PercpuArray
                && map.key_size() == 4
                && info.info.max_entries == 1,
            "unsupported Mitosis cpu_ctxs map shape"
        );
        ensure!(
            info.info.btf_id != 0 && info.info.btf_id == program.btf_id,
            "Mitosis CPU map BTF does not match its callback"
        );
        let btf = Btf::from_prog_id(program_id)?;
        let value: BtfType = btf
            .type_by_id(TypeId::from(info.info.btf_value_type_id))
            .context("CPU map value type is unavailable")?;
        let value = Struct::try_from(value.skip_mods_and_typedefs())
            .ok()
            .context("CPU map value is not a struct")?;
        let member = value
            .iter()
            .find(|member| member.name.and_then(|name| name.to_str()) == Some("cell"))
            .context("CPU map has no cell owner field")?;
        let MemberAttr::Normal { offset } = member.attr else {
            anyhow::bail!("CPU cell owner is a bitfield");
        };
        let ty: BtfType = btf
            .type_by_id(member.ty)
            .context("CPU cell type is unavailable")?;
        let ty = Int::try_from(ty.skip_mods_and_typedefs())
            .ok()
            .context("CPU cell owner is not an integer")?;
        ensure!(
            offset % 8 == 0 && ty.bits == 32 && ty.size() == 4,
            "CPU cell owner must be a byte-aligned 32-bit integer"
        );
        let cell_offset = (offset / 8) as usize;
        ensure!(
            cell_offset + 4 <= map.value_size() as usize,
            "CPU cell owner exceeds map value"
        );
        Ok(Self { map, cell_offset })
    }

    pub fn read(&self, cpu_ids: &[u32]) -> Result<BTreeMap<u32, u32>> {
        let values = self
            .map
            .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)?
            .context("Mitosis CPU ownership is unavailable")?;
        project_owners(&values, cpu_ids, self.cell_offset)
    }
}

fn project_owners(
    values: &[Vec<u8>],
    cpu_ids: &[u32],
    offset: usize,
) -> Result<BTreeMap<u32, u32>> {
    cpu_ids
        .iter()
        .map(|cpu| {
            let value = values
                .get(*cpu as usize)
                .with_context(|| format!("CPU {cpu} map slot is unavailable"))?;
            let bytes = value
                .get(offset..offset + 4)
                .context("CPU owner field is truncated")?;
            Ok((*cpu, u32::from_ne_bytes(bytes.try_into().unwrap())))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owners_use_the_validated_offset_and_real_cpu_ids() {
        let values = [0u32, 7, 2].map(|owner| {
            let mut value = vec![255; 16];
            value[8..12].copy_from_slice(&owner.to_ne_bytes());
            value
        });
        assert_eq!(
            project_owners(&values, &[0, 2], 8).unwrap(),
            BTreeMap::from([(0, 0), (2, 2)])
        );
        assert!(project_owners(&values, &[3], 8).is_err());
        assert!(project_owners(&values, &[0], 14).is_err());
    }
}
