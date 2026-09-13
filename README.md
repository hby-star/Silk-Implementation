# Silk Implementation

Rust implementations of the Silk randomness beacon and bAVSS-PO protocol, with
Rondo and Spurt for comparison.

## Setup

Install Python 3.12+ and [uv](https://docs.astral.sh/uv/). From the repository root:

```sh
cd experiments
uv sync --locked
```

Run all commands below from `experiments/`. Use a unique `--run-name` for each
experiment; it labels the saved results.

## Local Docker

Simulate a distributed protocol environment on one local machine using Docker
containers. Each node runs the protocol in its own container and communicates
with the other nodes over a Docker network. Network delay and bandwidth limits
simulate distributed network conditions.

Install and start Docker with Linux containers enabled, then run:

```sh
uv run fab local --run-name silk-local-n16
```

With the supplied configuration, this builds the image and runs Silk with 16
nodes for 2 epochs, producing 4 outputs per node. The runner collects logs,
validates the results, and removes the containers when the experiment finishes.

Configuration: `definitions/docker/beacon-performance.toml`. Edit `[smoke]` to
change the node count, threshold, batch size, or epoch count. Network and resource
limits are set in `[matrix.network]` and `[matrix.resources]` and also apply to
the quick run. To run Silk across the configurations in `[[matrix.cells]]`:

```sh
uv run fab local --mode matrix --run-name silk-local-matrix
```

Add `--implementation rondo-beacon` or `--implementation spurt-beacon` to select
another protocol.

## AWS

Run the distributed protocol across separate AWS EC2 instances communicating
over the real network.

Install Rust through rustup and install Zig. Ensure `cargo` and `zig` are on
`PATH`, then prepare the cross-build tools:

```sh
rustup target add x86_64-unknown-linux-musl
cargo install --locked cargo-zigbuild
```

Configure a default AWS credentials profile, for example with `aws configure`
if the AWS CLI is installed. The account must have EC2 permissions and sufficient
regional instance quotas.

Create the local settings file:

```sh
cp definitions/aws/settings.example.yaml definitions/aws/settings.yaml
```

Edit `key.name` (EC2 key-pair name), `key.path` (local private-key path), and
`instances.regions`. Import the same SSH public key under that key-pair name in
every selected region. Keep the provided instance settings: `t3a.medium`,
24 GiB volume, and TCP port 9000.

Start the n=16 Silk experiment:

```sh
uv run fab remote --settings definitions/aws/settings.yaml --nodes 16 --protocols silk-beacon --run-name silk-aws-n16 --timeout-seconds 3600
```

This runs 3 repetitions of 400 outputs per node, with batch size 50. Workload
parameters are in `definitions/aws/beacon-performance.toml`. Use `--nodes 16,31`
to select multiple sizes or `--protocols silk-beacon,rondo-beacon,spurt-beacon`
to compare protocols.

AWS resources are created and removed automatically. After an interrupted run,
clean up using its run name in the state path:

```sh
uv run fab remote-cleanup --state ../output/build/silk-aws-n16
```

## Results

From `experiments/`, results are under `../output/experiments/`:

- `raw/beacon-performance/<protocol>/<run-id>/`: node logs and the run manifest.
- `processed/beacon-performance/<protocol>/<run-id>/`: validation reports and CSV results.

Check that `node-validation.json` reports `"run_valid": true`.
`run-results.csv` contains the validated run summary. Matrix runs have separate
run IDs for each configuration and repetition. Plotting scripts are in `plots/`.
