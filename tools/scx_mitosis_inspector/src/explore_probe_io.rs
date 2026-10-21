use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::ptr;

use anyhow::{ensure, Context, Result};
use libbpf_rs::{libbpf_sys, MapCore, MapType, Object};

const BATCH_ENTRIES: usize = 1024;
const MAX_EINTR_RETRIES: usize = 8;

#[derive(Debug)]
struct BatchLayout {
    key_size: usize,
    value_size: usize,
    batch_entries: usize,
    cursor_size: usize,
    key_bytes: usize,
    value_bytes: usize,
    capacity: usize,
}

impl BatchLayout {
    fn new(
        map_type: MapType,
        key_size: usize,
        value_size: usize,
        max_entries: usize,
        capacity: usize,
    ) -> Result<Self> {
        ensure!(
            matches!(map_type, MapType::Hash | MapType::LruHash),
            "batched Explore reads require Hash or LruHash maps, found {map_type:?}"
        );
        ensure!(
            key_size > 0 && value_size > 0 && max_entries > 0 && capacity > 0,
            "map key size, value size, maximum entries, and read capacity must be nonzero"
        );
        let batch_entries = BATCH_ENTRIES.min(max_entries).min(capacity);
        let key_bytes = key_size
            .checked_mul(batch_entries)
            .context("batch key buffer size overflow")?;
        let value_bytes = value_size
            .checked_mul(batch_entries)
            .context("batch value buffer size overflow")?;
        Ok(Self {
            key_size,
            value_size,
            batch_entries,
            // Hash maps use an opaque u32 bucket cursor, even for smaller keys.
            cursor_size: key_size.max(4),
            key_bytes,
            value_bytes,
            capacity,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum BatchStatus {
    Continue(usize),
    Finished(usize),
    Retry,
}

fn batch_status(ret: i32, errno: Option<i32>, count: u32, requested: u32) -> Result<BatchStatus> {
    ensure!(ret <= 0, "unexpected BPF batch lookup return value {ret}");
    let finished = if ret == 0 {
        false
    } else {
        let errno = errno.context("BPF batch lookup failed without errno")?;
        ensure!(
            errno > 0,
            "BPF batch lookup failed with invalid errno {errno}"
        );
        // libbpf returns -errno and also sets errno, rather than returning -1.
        ensure!(
            ret == -errno,
            "BPF batch lookup return {ret} disagrees with errno {errno}"
        );
        if errno == libc::EINTR {
            // No output from an interrupted attempt is consumed before retrying.
            return Ok(BatchStatus::Retry);
        }
        if errno != libc::ENOENT {
            return Err(std::io::Error::from_raw_os_error(errno).into());
        }
        true
    };
    ensure!(requested > 0, "BPF batch lookup request must be nonzero");
    ensure!(
        count <= requested,
        "BPF batch lookup count {count} exceeds requested count {requested}"
    );
    if finished {
        // ENOENT can accompany a partial or full final batch, not just an empty one.
        Ok(BatchStatus::Finished(count as usize))
    } else {
        ensure!(count > 0, "BPF batch lookup made no progress");
        // A successful short hash batch may have stopped before a bucket that
        // would not fit. Its out_batch cursor must still be used for another call.
        Ok(BatchStatus::Continue(count as usize))
    }
}

fn retry_interrupted(retries: usize) -> Result<usize> {
    ensure!(
        retries < MAX_EINTR_RETRIES,
        "BPF batch lookup repeatedly interrupted ({MAX_EINTR_RETRIES} retries)"
    );
    Ok(retries + 1)
}

fn validate_cursor_progress(previous: &[u8], next: &[u8], started: bool) -> Result<()> {
    ensure!(
        !started || previous != next,
        "BPF batch lookup continuation cursor did not advance"
    );
    Ok(())
}

fn append_batch(
    result: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    layout: &BatchLayout,
    keys: &[u8],
    values: &[u8],
    count: usize,
    rows_seen: &mut usize,
) -> Result<()> {
    ensure!(
        count <= layout.batch_entries,
        "BPF batch count exceeds buffer capacity"
    );
    let total_rows = rows_seen
        .checked_add(count)
        .context("BPF map row count overflow")?;
    ensure!(
        total_rows <= layout.capacity,
        "BPF map read exceeds capacity {} before reaching its end",
        layout.capacity
    );
    let key_bytes = layout
        .key_size
        .checked_mul(count)
        .context("batch key buffer size overflow")?;
    let value_bytes = layout
        .value_size
        .checked_mul(count)
        .context("batch value buffer size overflow")?;
    ensure!(
        keys.len() >= key_bytes && values.len() >= value_bytes,
        "BPF batch count exceeds returned key or value buffer size"
    );
    for (key, value) in keys[..key_bytes]
        .chunks_exact(layout.key_size)
        .zip(values[..value_bytes].chunks_exact(layout.value_size))
    {
        result.insert(key.to_vec(), value.to_vec());
    }
    // Count all visited rows, including any duplicate keys seen while a map
    // changes, so concurrent updates cannot turn this into an unbounded read.
    *rows_seen = total_rows;
    Ok(())
}

/// Read an ordinary hash map from a loaded BPF object in bounded batches.
///
/// Syscall errors and capacity overflows return an error instead of partial data.
/// Concurrent BPF updates mean that a multi-batch read is not an atomic snapshot.
pub fn read_map(
    object: &Object,
    name: &str,
    capacity: usize,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let map = object
        .maps()
        .find(|map| map.name() == name)
        .with_context(|| format!("Explore BPF map {name} is unavailable"))?;
    read_hash_map(&map, capacity).with_context(|| format!("reading Explore BPF map {name}"))
}

/// Read a Hash or LruHash map, including a standalone MapHandle used for validation.
///
/// `capacity` bounds all rows visited. It is not treated as evidence of map
/// exhaustion: if a successful batch fills it, a terminal lookup is still needed.
pub fn read_hash_map(map: &impl MapCore, capacity: usize) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let layout = BatchLayout::new(
        map.map_type(),
        map.key_size() as usize,
        map.value_size() as usize,
        map.max_entries() as usize,
        capacity,
    )?;
    let buffer = |len: usize| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .context("allocating BPF batch buffer")?;
        bytes.resize(len, 0);
        Ok(bytes)
    };
    let mut keys = buffer(layout.key_bytes)?;
    let mut values = buffer(layout.value_bytes)?;
    let mut previous = buffer(layout.cursor_size)?;
    let mut next = buffer(layout.cursor_size)?;
    let opts = libbpf_sys::bpf_map_batch_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_batch_opts>() as _,
        ..Default::default()
    };
    let fd = map.as_fd();
    let mut result = BTreeMap::new();
    let mut rows_seen = 0;
    let mut started = false;
    let mut retries = 0;
    loop {
        // Reset count on every call, including retries after EINTR. Input and
        // output cursors use separate buffers so interrupted output is discarded.
        let mut count = layout.batch_entries as u32;
        // SAFETY: The borrowed fd stays alive throughout the lookup. Only ordinary
        // Hash/LruHash maps are accepted; buffers fit count * the actual key/value
        // strides, both cursors fit at least four bytes, and options/count are valid.
        let ret = unsafe {
            libbpf_sys::bpf_map_lookup_batch(
                fd.as_raw_fd(),
                if started {
                    previous.as_mut_ptr().cast()
                } else {
                    ptr::null_mut()
                },
                next.as_mut_ptr().cast(),
                keys.as_mut_ptr().cast(),
                values.as_mut_ptr().cast(),
                &mut count,
                &opts,
            )
        };
        // Capture errno immediately, before formatting errors or another call.
        let errno = if ret == 0 {
            None
        } else {
            std::io::Error::last_os_error().raw_os_error()
        };
        let (count, finished) = match batch_status(ret, errno, count, layout.batch_entries as u32)?
        {
            BatchStatus::Retry => {
                retries = retry_interrupted(retries)?;
                continue;
            }
            BatchStatus::Continue(count) => (count, false),
            BatchStatus::Finished(count) => (count, true),
        };
        if !finished {
            validate_cursor_progress(&previous, &next, started)?;
        }
        append_batch(&mut result, &layout, &keys, &values, count, &mut rows_seen)?;
        if finished {
            return Ok(result);
        }
        std::mem::swap(&mut previous, &mut next);
        started = true;
        retries = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_layout(capacity: usize) -> BatchLayout {
        BatchLayout {
            key_size: 4,
            value_size: 8,
            batch_entries: 4,
            cursor_size: 4,
            key_bytes: 16,
            value_bytes: 32,
            capacity,
        }
    }

    fn fixture_bytes(rows: &[(u32, u64)]) -> (Vec<u8>, Vec<u8>) {
        let mut keys = Vec::new();
        let mut values = Vec::new();
        for (key, value) in rows {
            keys.extend_from_slice(&key.to_ne_bytes());
            values.extend_from_slice(&value.to_ne_bytes());
        }
        (keys, values)
    }

    #[test]
    fn final_partial_batch_preserves_count() {
        assert_eq!(
            batch_status(-libc::ENOENT, Some(libc::ENOENT), 2, 4).unwrap(),
            BatchStatus::Finished(2)
        );
    }

    #[test]
    fn final_full_batch_preserves_count() {
        assert_eq!(
            batch_status(-libc::ENOENT, Some(libc::ENOENT), 4, 4).unwrap(),
            BatchStatus::Finished(4)
        );
    }

    #[test]
    fn empty_map_requires_terminal_enoent() {
        assert_eq!(
            batch_status(-libc::ENOENT, Some(libc::ENOENT), 0, 4).unwrap(),
            BatchStatus::Finished(0)
        );
        let error = batch_status(0, None, 0, 4).unwrap_err();
        assert!(error.to_string().contains("no progress"), "{error:#}");
    }

    #[test]
    fn successful_short_batch_continues_despite_stale_errno() {
        assert_eq!(
            batch_status(0, Some(libc::ENOENT), 2, 4).unwrap(),
            BatchStatus::Continue(2)
        );
    }

    #[test]
    fn syscall_errors_cannot_become_empty_maps() {
        for errno in [
            libc::EINVAL,
            libc::EFAULT,
            libc::EIO,
            libc::EBADF,
            libc::ENOSPC,
        ] {
            let error = batch_status(-errno, Some(errno), 0, 4).unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::raw_os_error),
                Some(errno),
                "{error:#}"
            );
        }
    }

    #[test]
    fn failed_batch_never_trusts_partial_count() {
        let error = batch_status(-libc::EFAULT, Some(libc::EFAULT), u32::MAX, 4).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error),
            Some(libc::EFAULT)
        );
    }

    #[test]
    fn malformed_count_is_rejected_for_success_and_enoent() {
        for (ret, errno) in [(0, None), (-libc::ENOENT, Some(libc::ENOENT))] {
            let error = batch_status(ret, errno, 5, 4).unwrap_err();
            assert!(error.to_string().contains("count"), "{error:#}");
        }
    }

    #[test]
    fn interrupted_batch_retries_without_trusting_count() {
        assert_eq!(
            batch_status(-libc::EINTR, Some(libc::EINTR), u32::MAX, 4).unwrap(),
            BatchStatus::Retry
        );
    }

    #[test]
    fn interrupted_retries_have_a_finite_budget() {
        let mut retries = 0;
        for expected in 1..=MAX_EINTR_RETRIES {
            retries = retry_interrupted(retries).unwrap();
            assert_eq!(retries, expected);
        }
        let error = retry_interrupted(retries).unwrap_err();
        assert!(error.to_string().contains("interrupted"), "{error:#}");
    }

    #[test]
    fn unchanged_continuation_cursor_is_rejected() {
        let error = validate_cursor_progress(&[4, 0, 0, 0], &[4, 0, 0, 0], true).unwrap_err();
        assert!(error.to_string().contains("cursor"), "{error:#}");
    }

    #[test]
    fn first_cursor_may_be_zero() {
        validate_cursor_progress(&[0; 4], &[0; 4], false).unwrap();
        validate_cursor_progress(&[4, 0, 0, 0], &[9, 0, 0, 0], true).unwrap();
    }

    #[test]
    fn missing_errno_is_not_accepted_as_enoent() {
        let error = batch_status(-libc::ENOENT, None, 0, 4).unwrap_err();
        assert!(error.to_string().contains("errno"), "{error:#}");
    }

    #[test]
    fn inconsistent_errno_is_rejected() {
        let error = batch_status(-libc::EIO, Some(libc::ENOENT), 0, 4).unwrap_err();
        assert!(error.to_string().contains("disagrees"), "{error:#}");
    }

    #[test]
    fn nonzero_positive_return_is_rejected() {
        let error = batch_status(1, None, 1, 4).unwrap_err();
        assert!(error.to_string().contains("return"), "{error:#}");
    }

    #[test]
    fn hash_cursor_is_at_least_four_bytes() {
        let layout = BatchLayout::new(MapType::Hash, 1, 8, 16, 16).unwrap();
        assert_eq!(layout.cursor_size, 4);
        assert_eq!(layout.key_bytes, 16);
        let wide = BatchLayout::new(MapType::LruHash, 24, 128, 16, 16).unwrap();
        assert_eq!(wide.cursor_size, 24);
        assert_eq!(wide.key_bytes, 24 * 16);
        assert_eq!(wide.value_bytes, 128 * 16);
    }

    #[test]
    fn large_maps_use_bounded_chunks() {
        let layout = BatchLayout::new(MapType::Hash, 8, 192, 65_536, 65_536).unwrap();
        assert_eq!(layout.batch_entries, BATCH_ENTRIES);
        assert_eq!(layout.key_bytes, 8 * BATCH_ENTRIES);
        assert_eq!(layout.value_bytes, 192 * BATCH_ENTRIES);
        let small = BatchLayout::new(MapType::Hash, 4, 8, 64, 8).unwrap();
        assert_eq!(small.batch_entries, 8);
    }

    #[test]
    fn unsupported_map_types_are_rejected_before_reading() {
        for map_type in [MapType::PercpuHash, MapType::LruPercpuHash, MapType::Array] {
            let error = BatchLayout::new(map_type, 4, 8, 16, 16).unwrap_err();
            assert!(error.to_string().contains("Hash"), "{error:#}");
        }
    }

    #[test]
    fn zero_dimensions_or_capacity_are_rejected() {
        for (key_size, value_size, max_entries, capacity) in
            [(0, 8, 16, 16), (4, 0, 16, 16), (4, 8, 0, 16), (4, 8, 16, 0)]
        {
            let error =
                BatchLayout::new(MapType::Hash, key_size, value_size, max_entries, capacity)
                    .unwrap_err();
            assert!(error.to_string().contains("nonzero"), "{error:#}");
        }
    }

    #[test]
    fn buffer_size_overflow_is_rejected() {
        for (key_size, value_size) in [(usize::MAX, 8), (4, usize::MAX)] {
            let error = BatchLayout::new(MapType::Hash, key_size, value_size, 16, 16).unwrap_err();
            assert!(error.to_string().contains("overflow"), "{error:#}");
        }
    }

    #[test]
    fn parser_retains_only_reported_rows() {
        let (keys, values) = fixture_bytes(&[(9, 900), (3, 300), (77, 7700)]);
        let mut result = BTreeMap::new();
        let mut rows_seen = 0;
        append_batch(
            &mut result,
            &fixture_layout(4),
            &keys,
            &values,
            2,
            &mut rows_seen,
        )
        .unwrap();
        assert_eq!(rows_seen, 2);
        assert_eq!(result.len(), 2);
        assert_eq!(result[&3u32.to_ne_bytes().to_vec()], 300u64.to_ne_bytes());
        assert_eq!(result[&9u32.to_ne_bytes().to_vec()], 900u64.to_ne_bytes());
        assert!(!result.contains_key(&77u32.to_ne_bytes().to_vec()));
    }

    #[test]
    fn malformed_buffer_is_rejected_before_adding_rows() {
        let (keys, values) = fixture_bytes(&[(9, 900)]);
        for (bad_keys, bad_values) in [
            (&keys[..3], values.as_slice()),
            (keys.as_slice(), &values[..7]),
        ] {
            let mut result = BTreeMap::new();
            let mut rows_seen = 0;
            let error = append_batch(
                &mut result,
                &fixture_layout(4),
                bad_keys,
                bad_values,
                1,
                &mut rows_seen,
            )
            .unwrap_err();
            assert!(error.to_string().contains("buffer"), "{error:#}");
            assert!(result.is_empty());
            assert_eq!(rows_seen, 0);
        }
    }

    #[test]
    fn capacity_overflow_is_rejected_before_adding_rows() {
        let (keys, values) = fixture_bytes(&[(9, 900), (3, 300)]);
        let mut result = BTreeMap::new();
        let mut rows_seen = 0;
        let error = append_batch(
            &mut result,
            &fixture_layout(1),
            &keys,
            &values,
            2,
            &mut rows_seen,
        )
        .unwrap_err();
        assert!(error.to_string().contains("capacity"), "{error:#}");
        assert!(result.is_empty());
        assert_eq!(rows_seen, 0);
    }

    #[test]
    fn duplicate_rows_still_consume_the_capacity_budget() {
        let (keys, values) = fixture_bytes(&[(9, 900)]);
        let mut result = BTreeMap::new();
        let mut rows_seen = 0;
        let layout = fixture_layout(1);
        append_batch(&mut result, &layout, &keys, &values, 1, &mut rows_seen).unwrap();
        let error =
            append_batch(&mut result, &layout, &keys, &values, 1, &mut rows_seen).unwrap_err();
        assert!(error.to_string().contains("capacity"), "{error:#}");
        assert_eq!(result.len(), 1);
        assert_eq!(rows_seen, 1);
    }

    #[test]
    fn a_terminal_empty_batch_is_valid_after_reaching_capacity() {
        let (keys, values) = fixture_bytes(&[(9, 900)]);
        let mut result = BTreeMap::new();
        let mut rows_seen = 0;
        let layout = fixture_layout(1);
        append_batch(&mut result, &layout, &keys, &values, 1, &mut rows_seen).unwrap();
        append_batch(&mut result, &layout, &[], &[], 0, &mut rows_seen).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(rows_seen, 1);
    }
}
