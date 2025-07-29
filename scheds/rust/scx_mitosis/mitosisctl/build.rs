fn main() {
    scx_utils::BpfBuilder::new()
        .unwrap()
        .enable_intf("../src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("../src/bpf/mitosis.bpf.c", "bpf")
        .build()
        .unwrap();
}
