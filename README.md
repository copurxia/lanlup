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
| `artstation-rs` | [![Gitea artstation-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/artstation-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/artstation-rs-wasip1.yml) |
| `bofmeta-rs` | [![Gitea bofmeta-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/bofmeta-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/bofmeta-rs-wasip1.yml) |
| `btvmeta-rs` | [![Gitea btvmeta-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/btvmeta-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/btvmeta-rs-wasip1.yml) |
| `comicinfo-rs` | [![Gitea comicinfo-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/comicinfo-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/comicinfo-rs-wasip1.yml) |
| `ehdb-rs` | [![Gitea ehdb-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/ehdb-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/ehdb-rs-wasip1.yml) |
| `ehdl-rs` | [![Gitea ehdl-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/ehdl-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/ehdl-rs-wasip1.yml) |
| `ehentai-rs` | [![Gitea ehentai-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/ehentai-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/ehentai-rs-wasip1.yml) |
| `ehlogin-rs` | [![Gitea ehlogin-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/ehlogin-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/ehlogin-rs-wasip1.yml) |
| `helloworld-rs` | [![Gitea helloworld-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/helloworld-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/helloworld-rs-wasip1.yml) |
| `nfo-rs` | [![Gitea nfo-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/nfo-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/nfo-rs-wasip1.yml) |
| `nhentai-rs` | [![Gitea nhentai-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/nhentai-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/nhentai-rs-wasip1.yml) |
| `nhlogin-rs` | [![Gitea nhlogin-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/nhlogin-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/nhlogin-rs-wasip1.yml) |
| `nhmeta-rs` | [![Gitea nhmeta-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/nhmeta-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/nhmeta-rs-wasip1.yml) |
| `opfmeta-rs` | [![Gitea opfmeta-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/opfmeta-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/opfmeta-rs-wasip1.yml) |
| `pixivdl-rs` | [![Gitea pixivdl-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/pixivdl-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/pixivdl-rs-wasip1.yml) |
| `pixivlogin-rs` | [![Gitea pixivlogin-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/pixivlogin-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/pixivlogin-rs-wasip1.yml) |
| `pixivmeta-rs` | [![Gitea pixivmeta-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/pixivmeta-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/pixivmeta-rs-wasip1.yml) |
| `tagmerge-rs` | [![Gitea tagmerge-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/tagmerge-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/tagmerge-rs-wasip1.yml) |
| `xdl-rs` | [![Gitea xdl-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/xdl-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/xdl-rs-wasip1.yml) |
| `xlogin-rs` | [![Gitea xlogin-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/xlogin-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/xlogin-rs-wasip1.yml) |
| `xmeta-rs` | [![Gitea xmeta-rs](https://git.copur.xyz/copur/lanlup/actions/workflows/xmeta-rs-wasip1.yml/badge.svg?branch=master)](https://git.copur.xyz/copur/lanlup/actions/workflows/xmeta-rs-wasip1.yml) |
