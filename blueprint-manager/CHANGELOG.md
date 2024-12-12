# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/tangle-network/gadget/compare/blueprint-manager-v0.2.1...blueprint-manager-v0.2.2) - 2024-12-12

### Other

- Call ID Insertion and Resolution For [#520](https://github.com/tangle-network/gadget/pull/520) ([#533](https://github.com/tangle-network/gadget/pull/533))

## [0.2.1](https://github.com/tangle-network/gadget/compare/blueprint-manager-v0.2.0...blueprint-manager-v0.2.1) - 2024-12-04

### Other

- updated the following local packages: gadget-sdk

## [0.2.0](https://github.com/tangle-network/gadget/compare/blueprint-manager-v0.1.3...blueprint-manager-v0.2.0) - 2024-11-29

### Other

- *(gadget-sdk)* [**breaking**] update to latest tangle ([#503](https://github.com/tangle-network/gadget/pull/503))

## [0.1.3](https://github.com/tangle-network/gadget/compare/blueprint-manager-v0.1.2...blueprint-manager-v0.1.3) - 2024-11-20

### Other

- updated the following local packages: gadget-sdk

## [0.1.2](https://github.com/tangle-network/gadget/compare/blueprint-manager-v0.1.1...blueprint-manager-v0.1.2) - 2024-11-16

### Other

- updated the following local packages: gadget-sdk

## [0.1.1](https://github.com/tangle-network/gadget/releases/tag/blueprint-manager-v0.1.1) - 2024-11-08

### Added

- [**breaking**] Refactor EventFlows for EVM and Remove EventWatchers ([#423](https://github.com/tangle-network/gadget/pull/423))
- symbiotic initial integration ([#411](https://github.com/tangle-network/gadget/pull/411))
- add optional data dir to blueprint manager ([#342](https://github.com/tangle-network/gadget/pull/342))
- eigenlayer incredible squaring blueprint and test ([#312](https://github.com/tangle-network/gadget/pull/312))
- add EVM Provider and Tangle Client Context Extensions ([#319](https://github.com/tangle-network/gadget/pull/319))
- Keystore Context Extensions ([#316](https://github.com/tangle-network/gadget/pull/316))
- add benchmarking mode ([#248](https://github.com/tangle-network/gadget/pull/248))

### Fixed

- *(gadget-sdk)* [**breaking**] prevent duplicate and self-referential messages ([#458](https://github.com/tangle-network/gadget/pull/458))
- *(sdk)* [**breaking**] allow for zero-based `blueprint_id` ([#426](https://github.com/tangle-network/gadget/pull/426))
- *(cargo-tangle)* CLI bugs ([#409](https://github.com/tangle-network/gadget/pull/409))
- *(sdk)* [**breaking**] downgrade substrate dependencies for now
- add `data_dir` back to `GadgetConfiguration` ([#350](https://github.com/tangle-network/gadget/pull/350))

### Other

- set blueprint-manager publishable ([#462](https://github.com/tangle-network/gadget/pull/462))
- add a p2p test for testing the networking layer ([#450](https://github.com/tangle-network/gadget/pull/450))
- Continue Improving Event Flows ([#399](https://github.com/tangle-network/gadget/pull/399))
- improve blueprint-manager and blueprint-test-utils ([#421](https://github.com/tangle-network/gadget/pull/421))
- Leverage blueprint in incredible squaring aggregator ([#365](https://github.com/tangle-network/gadget/pull/365))
- Event Listener Upgrade + Wrapper Types + sdk::main macro ([#333](https://github.com/tangle-network/gadget/pull/333))
- docs fix spelling issues ([#336](https://github.com/tangle-network/gadget/pull/336))
- Event listener ([#317](https://github.com/tangle-network/gadget/pull/317))
- Remove Logger ([#311](https://github.com/tangle-network/gadget/pull/311))
- Streamline keystore, cleanup testing, refactor blueprint manager, add tests, remove unnecessary code ([#285](https://github.com/tangle-network/gadget/pull/285))
- CI Improvements ([#301](https://github.com/tangle-network/gadget/pull/301))
- [feat] Gadget Metadata ([#274](https://github.com/tangle-network/gadget/pull/274))
- [MEGA PR] Overhaul repo, add Eigenlayer AVS example, remove many crates, add testing, remove unused code ([#246](https://github.com/tangle-network/gadget/pull/246))
- Add mpc blueprint starting point, cleanup abstractions ([#252](https://github.com/tangle-network/gadget/pull/252))
- Add more checks to CI ([#244](https://github.com/tangle-network/gadget/pull/244))
- [feat] benchmark proc-macro ([#238](https://github.com/tangle-network/gadget/pull/238))
- Spelling fix
- Promote all dependencies to workspace ([#233](https://github.com/tangle-network/gadget/pull/233))
- Make `{core, io, common}` no_std and WASM compatible ([#231](https://github.com/tangle-network/gadget/pull/231))
- Remove shell sdk and put inside blueprint manager ([#229](https://github.com/tangle-network/gadget/pull/229))
- Blueprint testing ([#206](https://github.com/tangle-network/gadget/pull/206))
