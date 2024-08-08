# Gadget: A Powerful distributed AVS Framework

<p align="center">
  <img src="https://github.com/webb-tools/dkg-substrate/raw/master/assets/webb_banner_light.png" alt="Gadget Logo">
</p>

[![Validate PR](https://github.com/webb-tools/gadget/actions/workflows/validate_pr.yml/badge.svg)](https://github.com/webb-tools/gadget/actions/workflows/validate_pr.yml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust Version](https://img.shields.io/badge/rust-1.74.0%2B-blue.svg)](https://www.rust-lang.org)

Gadget is a comprehensive framework for building multi-party computation (MPC) and restaking service gadgets. It provides a standardized and flexible approach to implementing services that interact with job management systems, such as blockchains with on-chain job management logic, and communicate with other service providers using peer-to-peer or alternative networking stacks.

## Features

- Modular and extensible architecture
- Support for various MPC protocols and services:
    - [x] [DFNS CGGMP21](https://github.com/dfns/cggmp21/tree/m/cggmp21)
    - [x] [Threshold BLS](https://github.com/hyperledger-labs/agora-blsful)
    - [x] [LIT Protocol fork of ZCash Frost](https://github.com/LIT-Protocol/frost)
    - [x] [Groth16 ZK-SaaS](https://github.com/webb-tools/zk-SaaS)
    - [x] [DKLS](https://github.com/webb-tools/silent-shard-dkls23-gadget)
- Integration with Substrate blockchain logic and networking
- Standardized job allocation, completion, and submission mechanisms
- Protocol-specific blockchain connections, networking layers, and application logic
- Comprehensive testing framework

## Getting Started

### Prerequisites

- Rust 1.74.0 or higher
- Substrate blockchain with compatible job management and submission infrastructure

### Installation

1. Clone the repository:

```bash
git clone https://github.com/webb-tools/gadget/
cd gadget
```
   
2. Build the project:

```bash
cargo build --release
```

### Running the Gadget Shell
The gadget shell is a standalone application that provides a command-line interface for interacting with the Gadget and the blockchain. To run the shell, use the following command:

```bash
./target/release/blueprint-manager --protocols-config ./global_protocols.toml --shell-config shell-configs/local-testnet-0.toml -vvv
```

Before running that command, make sure that a [tangle](https://github.com/webb-tools/tangle/) node is running, otherwise, the shell will fail.

### Creating a New Protocol
To create a new protocol using Gadget, clone the [protocol-template](https://github.com/webb-tools/protocol-template) and begin hacking!

For examples of protocols using this template, check out our [protocol implementations](https://github.com/webb-tools/protocols)

## Testing
This repository contains unit tests and integration tests to validate the functionality of the Gadget framework and its interaction with the blockchain.

### Unit Testing
To run the tests, use the following command:
```bash
RUST_LOG=gadget=trace cargo nextest run
```

### Integration testing
Integration testing involves a multi-step process that includes running a tangle node, running multiple gadget shells each with a separate config, and submitting jobs manually.
To run the integration tests, make sure the aforementioned steps are followed for building the executables, then, follow these steps:

1. Run a tangle node from the [tangle repository](https://github.com/webb-tools/tangle/)
```bash
bash ./scripts/run-standalone-local.sh --clean 
```

2. Run Gadgets
```bash
bash ./scripts/run-gadget-local.sh
```

3. Once the shells are running, open a separate terminal, navigate to the tangle directory, and run:
```bash
cd types && yarn && ts-node playground.ts 
```

4. View the progress by navigating in a web browser [here](https://polkadot.js.org/apps/?rpc=ws://127.0.0.1:9944#/explorer)


## Troubleshooting

### GMP Issues
If you encounter linking errors related to libgmp (e.g., "could not find library -lgmp") when building on a Mac M1, follow these steps:

1. Install GMP using Homebrew:
```bash
brew install gmp
```
2. Set the LIBRARY_PATH and INCLUDE_PATH environment variables:
```bash
export LIBRARY_PATH=$LIBRARY_PATH:/opt/homebrew/lib
export INCLUDE_PATH=$INCLUDE_PATH:/opt/homebrew/include
```
Note: You need to set these environment variables each time you start a new shell session or append them to your .zshrc file.

## Contributing

We welcome contributions to Gadget! If you have any ideas, suggestions, or bug reports, please open an issue or submit a pull request.

## License
Gadget is licensed under the MIT License

## Acknowledgements
We would like to thank the following projects for their inspiration and contributions to this repository:

* [DFNS CGGMP21](https://github.com/dfns/cggmp21/)
* [Threshold BLS](https://github.com/mikelodder7/blsful)
* [LIT Protocol fork of ZCash Frost](https://github.com/LIT-Protocol/frost)
* [DKLS](https://github.com/silence-laboratories/silent-shard-dkls23-ll)

## Contact
If you have any questions or need further information, please contact the developers [here](https://webb.tools/)
