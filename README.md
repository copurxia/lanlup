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

### Per-plugin badges

| Plugin | CI |
|------|----|
| `artstation-rs` | [![GitHub artstation-rs](https://github.com/copurxia/lanlup/actions/workflows/artstation-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/artstation-rs-wasip1.yml) |
| `bofmeta-rs` | [![GitHub bofmeta-rs](https://github.com/copurxia/lanlup/actions/workflows/bofmeta-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/bofmeta-rs-wasip1.yml) |
| `btvmeta-rs` | [![GitHub btvmeta-rs](https://github.com/copurxia/lanlup/actions/workflows/btvmeta-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/btvmeta-rs-wasip1.yml) |
| `comicinfo-rs` | [![GitHub comicinfo-rs](https://github.com/copurxia/lanlup/actions/workflows/comicinfo-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/comicinfo-rs-wasip1.yml) |
| `ehdb-rs` | [![GitHub ehdb-rs](https://github.com/copurxia/lanlup/actions/workflows/ehdb-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/ehdb-rs-wasip1.yml) |
| `ehdl-rs` | [![GitHub ehdl-rs](https://github.com/copurxia/lanlup/actions/workflows/ehdl-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/ehdl-rs-wasip1.yml) |
| `ehentai-rs` | [![GitHub ehentai-rs](https://github.com/copurxia/lanlup/actions/workflows/ehentai-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/ehentai-rs-wasip1.yml) |
| `ehlogin-rs` | [![GitHub ehlogin-rs](https://github.com/copurxia/lanlup/actions/workflows/ehlogin-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/ehlogin-rs-wasip1.yml) |
| `helloworld-rs` | [![GitHub helloworld-rs](https://github.com/copurxia/lanlup/actions/workflows/helloworld-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/helloworld-rs-wasip1.yml) |
| `nfo-rs` | [![GitHub nfo-rs](https://github.com/copurxia/lanlup/actions/workflows/nfo-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/nfo-rs-wasip1.yml) |
| `nhentai-rs` | [![GitHub nhentai-rs](https://github.com/copurxia/lanlup/actions/workflows/nhentai-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/nhentai-rs-wasip1.yml) |
| `nhlogin-rs` | [![GitHub nhlogin-rs](https://github.com/copurxia/lanlup/actions/workflows/nhlogin-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/nhlogin-rs-wasip1.yml) |
| `nhmeta-rs` | [![GitHub nhmeta-rs](https://github.com/copurxia/lanlup/actions/workflows/nhmeta-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/nhmeta-rs-wasip1.yml) |
| `opfmeta-rs` | [![GitHub opfmeta-rs](https://github.com/copurxia/lanlup/actions/workflows/opfmeta-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/opfmeta-rs-wasip1.yml) |
| `pixivdl-rs` | [![GitHub pixivdl-rs](https://github.com/copurxia/lanlup/actions/workflows/pixivdl-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/pixivdl-rs-wasip1.yml) |
| `pixivlogin-rs` | [![GitHub pixivlogin-rs](https://github.com/copurxia/lanlup/actions/workflows/pixivlogin-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/pixivlogin-rs-wasip1.yml) |
| `pixivmeta-rs` | [![GitHub pixivmeta-rs](https://github.com/copurxia/lanlup/actions/workflows/pixivmeta-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/pixivmeta-rs-wasip1.yml) |
| `tagmerge-rs` | [![GitHub tagmerge-rs](https://github.com/copurxia/lanlup/actions/workflows/tagmerge-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/tagmerge-rs-wasip1.yml) |
| `xdl-rs` | [![GitHub xdl-rs](https://github.com/copurxia/lanlup/actions/workflows/xdl-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/xdl-rs-wasip1.yml) |
| `xlogin-rs` | [![GitHub xlogin-rs](https://github.com/copurxia/lanlup/actions/workflows/xlogin-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/xlogin-rs-wasip1.yml) |
| `xmeta-rs` | [![GitHub xmeta-rs](https://github.com/copurxia/lanlup/actions/workflows/xmeta-rs-wasip1.yml/badge.svg?branch=master)](https://github.com/copurxia/lanlup/actions/workflows/xmeta-rs-wasip1.yml) |
