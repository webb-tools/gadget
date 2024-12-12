# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.2](https://github.com/tangle-network/gadget/compare/gadget-sdk-v0.6.1...gadget-sdk-v0.6.2) - 2024-12-12

### Other

- Download Tangle binary against specific hash ([#537](https://github.com/tangle-network/gadget/pull/537))
- Call ID Insertion and Resolution For [#520](https://github.com/tangle-network/gadget/pull/520) ([#533](https://github.com/tangle-network/gadget/pull/533))

## [0.6.1](https://github.com/tangle-network/gadget/compare/gadget-sdk-v0.6.0...gadget-sdk-v0.6.1) - 2024-12-04

### Added

- *(cargo-tangle)* eigenlayer templates ([#501](https://github.com/tangle-network/gadget/pull/501))

## [0.6.0](https://github.com/tangle-network/gadget/compare/gadget-sdk-v0.5.1...gadget-sdk-v0.6.0) - 2024-11-29

### Added

- add MPCContext derive + test utils refactor ([#497](https://github.com/tangle-network/gadget/pull/497))

### Fixed

- *(gadget-blueprint-serde)* [**breaking**] handle bytes properly ([#500](https://github.com/tangle-network/gadget/pull/500))
- *(gadget-sdk)* use the right field for container status

### Other

- [**breaking**] update `eigensdk` ([#506](https://github.com/tangle-network/gadget/pull/506))
- *(gadget-sdk)* [**breaking**] update to latest tangle ([#503](https://github.com/tangle-network/gadget/pull/503))

## [0.5.1](https://github.com/tangle-network/gadget/compare/gadget-sdk-v0.5.0...gadget-sdk-v0.5.1) - 2024-11-20

### Added

- add more service ctx methods for Tangle ([#477](https://github.com/tangle-network/gadget/pull/477))

### Fixed

- race conditions in multiplexer ([#486](https://github.com/tangle-network/gadget/pull/486))

## [0.5.0](https://github.com/tangle-network/gadget/compare/gadget-sdk-v0.4.0...gadget-sdk-v0.5.0) - 2024-11-16

### Added

- Add utils for blueprints: hashing, config convenience functions ([#476](https://github.com/tangle-network/gadget/pull/476))
- improved eigenlayer context and testing ([#453](https://github.com/tangle-network/gadget/pull/453))
- *(gadget-sdk)* [**breaking**] integrate `blueprint-serde` ([#469](https://github.com/tangle-network/gadget/pull/469))
- *(gadget-sdk)* [**breaking**] add more Docker utils ([#466](https://github.com/tangle-network/gadget/pull/466))
- add IN_ADDR_ANY for V4 and V6  ([#461](https://github.com/tangle-network/gadget/pull/461))

### Other

- *(macros)* cleanup macros, add better error handling, dedup code, DX ([#472](https://github.com/tangle-network/gadget/pull/472))
- enable `format_code_in_doc_comments` for rustfmt ([#467](https://github.com/tangle-network/gadget/pull/467))

## [0.4.0](https://github.com/tangle-network/gadget/compare/gadget-sdk-v0.3.0...gadget-sdk-v0.4.0) - 2024-11-08

### Fixed

- *(gadget-sdk)* [**breaking**] prevent duplicate and self-referential messages ([#458](https://github.com/tangle-network/gadget/pull/458))
- *(ci)* add doc tests to CI ([#383](https://github.com/tangle-network/gadget/pull/383))
- handle edge cases during registration ([#452](https://github.com/tangle-network/gadget/pull/452))

### Other

- add a p2p test for testing the networking layer ([#450](https://github.com/tangle-network/gadget/pull/450))
- Improve code for next documentation update. ([#434](https://github.com/tangle-network/gadget/pull/434))
- improve test-utils and lower networking log level ([#448](https://github.com/tangle-network/gadget/pull/448))

## [0.3.0](https://github.com/tangle-network/gadget/compare/gadget-sdk-v0.2.3...gadget-sdk-v0.3.0) - 2024-11-05

### Added

- [**breaking**] Refactor EventFlows for EVM and Remove EventWatchers ([#423](https://github.com/tangle-network/gadget/pull/423))
- *(gadget-sdk)* add TxProgressExt trait ([#425](https://github.com/tangle-network/gadget/pull/425))
- feat!(gadget-sdk): add an Error type for executor module ([#420](https://github.com/tangle-network/gadget/pull/420))
- symbiotic initial integration ([#411](https://github.com/tangle-network/gadget/pull/411))

### Fixed

- *(gadget-sdk)* update sdk and utilities for tangle avs ([#355](https://github.com/tangle-network/gadget/pull/355))
- *(gadget-sdk)* Return `Bytes` when using `Vec<u8>` in params and result ([#428](https://github.com/tangle-network/gadget/pull/428))
- *(sdk)* [**breaking**] allow for zero-based `blueprint_id` ([#426](https://github.com/tangle-network/gadget/pull/426))
- *(cargo-tangle)* CLI bugs ([#409](https://github.com/tangle-network/gadget/pull/409))

### Other

- Continue Improving Event Flows ([#399](https://github.com/tangle-network/gadget/pull/399))

## [0.2.3](https://github.com/tangle-network/gadget/compare/gadget-sdk-v0.2.2...gadget-sdk-v0.2.3) - 2024-10-25

### Added

- *(gadget-sdk)* add utilities for interacting with Docker ([#398](https://github.com/tangle-network/gadget/pull/398))
- *(cargo-tangle)* key generation ([#385](https://github.com/tangle-network/gadget/pull/385))

### Other

- Leverage blueprint in incredible squaring aggregator ([#365](https://github.com/tangle-network/gadget/pull/365))

## [0.2.2](https://github.com/tangle-network/gadget/compare/gadget-sdk-v0.2.1...gadget-sdk-v0.2.2) - 2024-10-24

### Other

- updated the following local packages: gadget-blueprint-proc-macro

## [0.2.1](https://github.com/tangle-network/gadget/compare/gadget-sdk-v0.2.0...gadget-sdk-v0.2.1) - 2024-10-24

### Added

- *(gadget-sdk)* improve `MultiJobRunner` builder ([#382](https://github.com/tangle-network/gadget/pull/382))

### Other

- Event Flows for Tangle ([#363](https://github.com/tangle-network/gadget/pull/363))

## [0.2.0](https://github.com/tangle-network/gadget/compare/gadget-sdk-v0.1.1...gadget-sdk-v0.2.0) - 2024-10-23

### Added

- expose bootnodes in GadgetConfiguration ([#366](https://github.com/tangle-network/gadget/pull/366))
- *(sdk)* re-export `libp2p`
- add optional data dir to blueprint manager ([#342](https://github.com/tangle-network/gadget/pull/342))
- eigenlayer incredible squaring blueprint and test ([#312](https://github.com/tangle-network/gadget/pull/312))
- allow env vars for `ContextConfig` args ([#339](https://github.com/tangle-network/gadget/pull/339))

### Fixed

- *(sdk)* updated keystore support and fixes ([#368](https://github.com/tangle-network/gadget/pull/368))
- *(sdk)* [**breaking**] downgrade substrate dependencies for now
- add `data_dir` back to `GadgetConfiguration` ([#350](https://github.com/tangle-network/gadget/pull/350))

### Other

- release ([#378](https://github.com/tangle-network/gadget/pull/378))
- release ([#362](https://github.com/tangle-network/gadget/pull/362))
- Fix eigenlayer example ([#375](https://github.com/tangle-network/gadget/pull/375))
- update to latest changes in tangle ([#367](https://github.com/tangle-network/gadget/pull/367))
- Event Workflows (phase 1: Custom listeners) ([#359](https://github.com/tangle-network/gadget/pull/359))
- Multi job runner + SDK main macro ([#346](https://github.com/tangle-network/gadget/pull/346))
- Event Listener Upgrade + Wrapper Types + sdk::main macro ([#333](https://github.com/tangle-network/gadget/pull/333))
- update naming ([#343](https://github.com/tangle-network/gadget/pull/343))
- Fix typos ([#329](https://github.com/tangle-network/gadget/pull/329))
- Event listener ([#317](https://github.com/tangle-network/gadget/pull/317))
- Return output from cmd exec ([#328](https://github.com/tangle-network/gadget/pull/328))
- release ([#314](https://github.com/tangle-network/gadget/pull/314))

## [0.1.2](https://github.com/tangle-network/gadget/compare/gadget-sdk-v0.1.1...gadget-sdk-v0.1.2) - 2024-09-30

### Other

- updated the following local packages: gadget-context-derive
