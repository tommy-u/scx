fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .compile_link_gen()
        .unwrap();
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_skel("src/bpf/explore.bpf.c", "explore_bpf")
        .build()
        .unwrap();
}
