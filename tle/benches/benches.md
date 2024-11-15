# Benchmarking Guide

Benchmarking is performed using [criterion](https://github.com/bheisler/criterion.rs). 

## Running

To execute benchmarks, run `cargo bench` from the root directory. 

The output can be found in `/target/criterion/your_bench_target`. It constructs html reports that can be viewed in a browser.

## Adding new Benches

To add a new bench:
1. create a new file under `tle/benches` for example `my_new_bench.rs`
2. register your benchmark in the tle Cargo.toml by adding:
``` toml
[[bench]]
name = "my_new_bench"
harness = false
```
