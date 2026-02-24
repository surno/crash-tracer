# crash-tracer

## Prerequisites

### Rust Nightly Toolchain

```bash
rustup toolchain install nightly
```

### Add rust-src for eBPF std library build support

```bash
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
```

### Install bpf-linker

Required for linking eBPF programs:

```bash
cargo +nightly install bpf-linker
```

## Build

```bash
cargo build
```
