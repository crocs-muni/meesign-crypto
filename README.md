# Build

There are couple of ways how to build this project.

## Build from source via Nix

To build via Nix run:
```bash
nix build
```

To enter a development environment, do:
```bash
nix develop
cargo build
```

## Build from source

The required dependencies are Rust, Protocol buffers, pcsclite. Then you can:
```bash
cargo build
```
