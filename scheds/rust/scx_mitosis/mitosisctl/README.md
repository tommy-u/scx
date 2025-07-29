# mitosisctl

`mitosisctl` provides simple access to `scx_mitosis` BPF maps. It can
list map names and get or set individual entries.

## Usage

```
mitosisctl list
mitosisctl get <MAP> <KEY>
mitosisctl set <MAP> <KEY> <VALUE>
```

Available maps correspond to the BPF maps defined by `scx_mitosis`.
