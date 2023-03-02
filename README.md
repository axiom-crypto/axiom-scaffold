# axiom-scaffold

This repository is intended to provide a playground for you to easily write a ZK circuit on top of the Axiom library.
Using Axiom, you can use ZK to trustlessly read historical Ethereum data and then run arbitrary computations on top.

## Getting started

Install rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone this repo:

```bash
git clone https://github.com/axiom-crypto/axiom-scaffold.git
cd axiom-scaffold
```

We need an archive node to fetch historical data to use as inputs for ZK circuits you write.
The default provider is Infura on Ethereum mainnet, and you can export your Infura project ID as an environment variable
by copying

```bash
cp .env_example .env
# fill in .env with your Infura project ID
source .env
```

If you want to use a different provider or switch to Goerli testnet, you can modify the beginning of [`main.rs`](src/main.rs).
We use the `Provider` type from [ethers-providers](https://crates.io/crates/ethers-providers).

## Axiom Playground

You can write your circuit in [`main.rs`](src/main.rs). We've provided some examples to get you started.
The core functionality is provided by the `AxiomChip` object, and you can use it to call any function in [`scaffold.rs`](src/scaffold.rs) (docs incoming).

When you are ready to run your circuit, you can run

```bash
DEGREE=<k> cargo run
```

where `DEGREE` is an environmental variable you set (if not provided it will default to `18`).
This specifies that the circuit you create will have `2^DEGREE` rows (in the PLONKish arithmetization); our library automatically configures the number of columns based on this.
You can play around with different `DEGREE` settings to find the one with the best performance for your circuit.

The above uses the `dev` profile with `opt-level=3` (faster performance than the default). For even faster performance with a small hit to compile time, you can run

```bash
DEGREE=<k> cargo run --profile=local
```

For fastest runtime performance, you can run

```bash
DEGREE=<k> cargo run --release
```

If you want to see mysterious statistics about your circuit, you can run

```bash
RUST_LOG=info DEGREE=<k> cargo run
```
