# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.3](https://github.com/tangle-network/gadget/compare/cargo-tangle-v0.3.2...cargo-tangle-v0.3.3) - 2024-12-12

### Added

- *(cargo-tangle)* improve error handling ([#523](https://github.com/tangle-network/gadget/pull/523))

### Other

- Download Tangle binary against specific hash ([#537](https://github.com/tangle-network/gadget/pull/537))

## [0.3.2](https://github.com/tangle-network/gadget/compare/cargo-tangle-v0.3.1...cargo-tangle-v0.3.2) - 2024-12-04

### Added

- *(cargo-tangle)* eigenlayer templates ([#501](https://github.com/tangle-network/gadget/pull/501))

## [0.3.1](https://github.com/tangle-network/gadget/compare/cargo-tangle-v0.3.0...cargo-tangle-v0.3.1) - 2024-11-29

### Other

- update Cargo.toml dependencies

## [0.3.0](https://github.com/tangle-network/gadget/compare/cargo-tangle-v0.2.4...cargo-tangle-v0.3.0) - 2024-11-20

### Added

- *(cargo-tangle)* [**breaking**] use Soldeer for dependencies ([#487](https://github.com/tangle-network/gadget/pull/487))

## [0.2.4](https://github.com/tangle-network/gadget/compare/cargo-tangle-v0.2.3...cargo-tangle-v0.2.4) - 2024-11-16

### Other

- fix changelog files ([#464](https://github.com/tangle-network/gadget/pull/464))

## [0.2.3](https://github.com/tangle-network/gadget/compare/cargo-tangle-v0.2.2...cargo-tangle-v0.2.3) - 2024-11-08

### Added

- *(cargo-tangle)* force initialize git submodules ([#457](https://github.com/tangle-network/gadget/pull/457))

## [0.2.2](https://github.com/tangle-network/gadget/compare/cargo-tangle-v0.2.1...cargo-tangle-v0.2.2) - 2024-11-05

### Added

- *(gadget-sdk)* add TxProgressExt trait ([#425](https://github.com/tangle-network/gadget/pull/425))

### Fixed

- *(cargo-tangle)* CLI bugs ([#409](https://github.com/tangle-network/gadget/pull/409))

### Other

- Continue Improving Event Flows ([#399](https://github.com/tangle-network/gadget/pull/399))

## [0.2.1](https://github.com/tangle-network/gadget/compare/cargo-tangle-v0.2.0...cargo-tangle-v0.2.1) - 2024-10-25

### Added

- *(cargo-tangle)* key generation ([#385](https://github.com/tangle-network/gadget/pull/385))

### Fixed

- *(cargo-tangle)* bake blueprint json ([#397](https://github.com/tangle-network/gadget/pull/397))

### Other

- Leverage blueprint in incredible squaring aggregator ([#365](https://github.com/tangle-network/gadget/pull/365))

## [0.2.0](https://github.com/tangle-network/gadget/compare/cargo-tangle-v0.1.3...cargo-tangle-v0.2.0) - 2024-10-24

### Added

- *(cargo-tangle)* [**breaking**] rename "gadget" to "blueprint" ([#384](https://github.com/tangle-network/gadget/pull/384))

### Other

- Event Flows for Tangle ([#363](https://github.com/tangle-network/gadget/pull/363))

## [0.1.3](https://github.com/tangle-network/gadget/compare/cargo-tangle-v0.1.2...cargo-tangle-v0.1.3) - 2024-10-23

### Added

- *(cli)* support custom repo and path sources ([#360](https://github.com/tangle-network/gadget/pull/360))

### Fixed

- *(sdk)* updated keystore support and fixes ([#368](https://github.com/tangle-network/gadget/pull/368))
- load substrate signer from env correctly ([#349](https://github.com/tangle-network/gadget/pull/349))

### Other

- release ([#378](https://github.com/tangle-network/gadget/pull/378))
- release ([#362](https://github.com/tangle-network/gadget/pull/362))
- update to latest changes in tangle ([#367](https://github.com/tangle-network/gadget/pull/367))
- Event Workflows (phase 1: Custom listeners) ([#359](https://github.com/tangle-network/gadget/pull/359))
- Event Listener Upgrade + Wrapper Types + sdk::main macro ([#333](https://github.com/tangle-network/gadget/pull/333))
- update naming ([#343](https://github.com/tangle-network/gadget/pull/343))
- release ([#314](https://github.com/tangle-network/gadget/pull/314))

## [0.1.2](https://github.com/tangle-network/gadget/releases/tag/cargo-tangle-v0.1.2) - 2024-09-30

### Other

- add CLI description to Cargo.toml ([#326](https://github.com/tangle-network/gadget/pull/326))
- release ([#313](https://github.com/tangle-network/gadget/pull/313))
- release ([#308](https://github.com/tangle-network/gadget/pull/308))
- Update READMEs with Download Links ([#302](https://github.com/tangle-network/gadget/pull/302))
- CI Improvements ([#301](https://github.com/tangle-network/gadget/pull/301))
- Expose executor from SDK ([#300](https://github.com/tangle-network/gadget/pull/300))
- Update README.md ([#287](https://github.com/tangle-network/gadget/pull/287))
- [MEGA PR] Overhaul repo, add Eigenlayer AVS example, remove many crates, add testing, remove unused code ([#246](https://github.com/tangle-network/gadget/pull/246))
- Promote all dependencies to workspace ([#233](https://github.com/tangle-network/gadget/pull/233))
- Remove shell sdk and put inside blueprint manager ([#229](https://github.com/tangle-network/gadget/pull/229))
- Blueprint testing ([#206](https://github.com/tangle-network/gadget/pull/206))
- Add CLI usage documentation to README ([#228](https://github.com/tangle-network/gadget/pull/228))
- Rename Gadget CLI to Tangle CLI ([#227](https://github.com/tangle-network/gadget/pull/227))
- Publish Gadget SDK to crates.io ([#215](https://github.com/tangle-network/gadget/pull/215))
- add signer selection to the CLI
- Add signers
- Deployment works!
- Add more to the deploy command
- working on deploy cmd
- rename cmds
- add cargo gadget generate cmd
- CLI

## [0.1.1-beta.7](https://github.com/tangle-network/gadget/releases/tag/cargo-tangle-v0.1.1-beta.7) - 2024-09-25

### Other

- Update READMEs with Download Links ([#302](https://github.com/tangle-network/gadget/pull/302))
- CI Improvements ([#301](https://github.com/tangle-network/gadget/pull/301))
- Expose executor from SDK ([#300](https://github.com/tangle-network/gadget/pull/300))
- Update README.md ([#287](https://github.com/tangle-network/gadget/pull/287))
- [MEGA PR] Overhaul repo, add Eigenlayer AVS example, remove many crates, add testing, remove unused code ([#246](https://github.com/tangle-network/gadget/pull/246))
- Promote all dependencies to workspace ([#233](https://github.com/tangle-network/gadget/pull/233))
- Remove shell sdk and put inside blueprint manager ([#229](https://github.com/tangle-network/gadget/pull/229))
- Blueprint testing ([#206](https://github.com/tangle-network/gadget/pull/206))
- Add CLI usage documentation to README ([#228](https://github.com/tangle-network/gadget/pull/228))
- Rename Gadget CLI to Tangle CLI ([#227](https://github.com/tangle-network/gadget/pull/227))
- Publish Gadget SDK to crates.io ([#215](https://github.com/tangle-network/gadget/pull/215))
- add signer selection to the CLI
- Add signers
- Deployment works!
- Add more to the deploy command
- working on deploy cmd
- rename cmds
- add cargo gadget generate cmd
- CLI
