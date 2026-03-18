# plugins-rs

Rust-based plugins workspace.

## Build (WASI Preview1)

Build a single plugin:

```bash
cd <plugin>-rs
rustup target add wasm32-wasip1
cargo build --locked --target wasm32-wasip1 --release
```

Artifact location:

- `target/wasm32-wasip1/release/*.wasm`

## CI

Each plugin has an independent workflow under:

- `.github/workflows/*-wasip1.yml`

All workflows call:

- `.github/workflows/_build-wasip1.yml`

The CI uploads artifact name:

- `<plugin>-wasip1`
