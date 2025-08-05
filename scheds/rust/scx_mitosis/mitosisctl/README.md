# mitosisctl

`mitosisctl` is a helper for inspecting and updating the BPF maps used by the
`scx_mitosis` scheduler.  It communicates with the running scheduler through
`bpftool` and exposes a small CLI for common tasks.

## Usage

```
mitosisctl list
mitosisctl get <MAP>
mitosisctl set <MAP> [-f FILE]
mitosisctl topology
```

- `list` shows the names of maps exported by `scx_mitosis`.
- `get` prints the contents of the specified map.
- `set` populates a map using the current CPU topology or from `FILE` if
  provided.  The file should contain `cpu,l3` entries and `-` can be used for
  stdin.
- `topology` displays the CPU to L3 mapping detected on the host.

Currently only the `cpu_to_l3` map is accessible.  Additional maps may be added
as the scheduler evolves.

## Building

The tool is part of the `scx` repository and can be built with the rest of the
project using `meson` or individually with `cargo build --release` from this
directory.

## Future Directions

* Support more `scx_mitosis` maps and operations.
* Ability to export map contents to files.
* Make L3 aware
