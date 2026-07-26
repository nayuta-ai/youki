# Webassembly

There are 3 things you need to do to run a WebAssembly module with youki.

1. Build youki with a wasm feature flag enabled
2. Build a container image with the WebAssembly module
3. Run the container with youki

## Build youki with `wasm-wasmedge`, `wasm-wasmer`, or `wasm-wasmtime` feature flag enabled

- Run `build.sh` with `-f wasm-wasmedge` option.

    ```bash
    ./scripts/build.sh -o . -r -f wasm-wasmedge
    ```

- Run `build.sh` with `-f wasm-wasmer` option.

    ```bash
    ./scripts/build.sh -o . -r -f wasm-wasmer
    ```

- Run `build.sh` with `-f wasm-wasmtime` option.

    ```bash
    ./scripts/build.sh -o . -r -f wasm-wasmtime
    ```

## Build a container image with the WebAssembly module

If you want to run a webassembly module with youki, your config.json has to include either `run.oci.handler` or `module.wasm.image/variant`.

It also needs to specify a valid `.wasm` (webassembly binary) or `.wat` (webassembly text) module as entrypoint for the container. If a `.wat` module is specified it will be compiled to a wasm module by youki before it is executed. The module also needs to be available in the root filesystem of the container.

```json
"ociVersion": "1.0.2-dev",
"annotations": {
    "run.oci.handler": "wasm"
},
"process": {
    "args": [
        "hello.wasm",
        "hello",
        "world"
    ]
}
```

### Compile a sample wasm module

A simple wasm module can be created by running

```console
rustup target add wasm32-wasip1
cargo new wasm-module --bin
cd ./wasm-module
vi src/main.rs
```

```rust
fn main() {
    println!("Printing args");
    for arg in std::env::args().skip(1) {
        println!("{}", arg);
    }

    println!("Printing envs");
    for envs in std::env::vars() {
        println!("{:?}", envs);
    }
}
```

Then compile the program to WASI.

```console
cargo build --target wasm32-wasip1
```

> **Note:** The `wasm32-wasi` target was removed in Rust 1.84. Use `wasm32-wasip1` instead.

### Build a container image with the module

The build context must be the youki repository root so that the compiled `.wasm` artifact (located under `target/`) is reachable. Use `-f` to point to the Dockerfile.

Create a Dockerfile at `tools/wasm-sample/Dockerfile` (or any path of your choice):

```Dockerfile
FROM scratch
COPY target/wasm32-wasip1/debug/wasm-module.wasm /
ENTRYPOINT ["wasm-module.wasm"]
```

Then build a container image with the `module.wasm.image/variant=compat` annotation from the youki root: [^1]

```console
sudo buildah build \
  --annotation "module.wasm.image/variant=compat" \
  -f tools/wasm-sample/Dockerfile \
  -t wasm-module \
  .
```

## Run the wasm module with youki and podman

Run podman with youki as runtime. [^1]

podman does not propagate image-level annotations into the OCI runtime spec automatically, so the annotation must be passed explicitly via `--annotation`:

```bash
sudo podman \
  --runtime /path/to/youki \
  run --rm \
  --annotation "module.wasm.image/variant=compat" \
  localhost/wasm-module 1 2 3
```

## Run the wasm module directly with youki

You can also run a WASM workload without a container manager by constructing an OCI bundle manually.

```bash
# 1. Create bundle directory structure
mkdir -p /tmp/wasm-bundle/rootfs
cp /path/to/wasm-module.wasm /tmp/wasm-bundle/rootfs/

# 2. Generate a base OCI spec
cd /tmp/wasm-bundle && youki spec

# 3. Add the WASM annotation and set args (edit config.json)
#    Set annotations["module.wasm.image/variant"] = "compat"
#    Set process.args = ["/wasm-module.wasm", "arg1", "arg2"]

# 4. Run
sudo youki run --bundle /tmp/wasm-bundle my-wasm-container
```

[^1]: You might need `sudo` because of [#719](https://github.com/youki-dev/youki/issues/719).
