# WASM compat

This crate provides wasm compatibility for the tle crate.

## Build

To compile to wasm, first build the project and them run wasm-pack

``` shell
cargo build
wasm-pack build --target web --out-dir pkg
```