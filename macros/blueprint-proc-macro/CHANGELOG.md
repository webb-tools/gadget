# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1](https://github.com/tangle-network/gadget/compare/gadget-blueprint-proc-macro-v0.5.0...gadget-blueprint-proc-macro-v0.5.1) - 2024-12-12

### Fixed

- *(blueprint-proc-macro)* fix bug where job IDs are not written in order to blueprint.json ([#542](https://github.com/tangle-network/gadget/pull/542))

### Other

- Download Tangle binary against specific hash ([#537](https://github.com/tangle-network/gadget/pull/537))
- Call ID Insertion and Resolution For [#520](https://github.com/tangle-network/gadget/pull/520) ([#533](https://github.com/tangle-network/gadget/pull/533))

## [0.5.0](https://github.com/tangle-network/gadget/compare/gadget-blueprint-proc-macro-v0.4.0...gadget-blueprint-proc-macro-v0.5.0) - 2024-11-29

### Fixed

- *(blueprint-proc-macro)* set `tokio` crate in `sdk::main` ([#502](https://github.com/tangle-network/gadget/pull/502))
- *(gadget-blueprint-serde)* [**breaking**] handle bytes properly ([#500](https://github.com/tangle-network/gadget/pull/500))

## [0.4.0](https://github.com/tangle-network/gadget/compare/gadget-blueprint-proc-macro-v0.3.1...gadget-blueprint-proc-macro-v0.4.0) - 2024-11-16

### Added

- *(gadget-sdk)* [**breaking**] integrate `blueprint-serde` ([#469](https://github.com/tangle-network/gadget/pull/469))

### Other

- *(macros)* cleanup macros, add better error handling, dedup code, DX ([#472](https://github.com/tangle-network/gadget/pull/472))

## [0.3.1](https://github.com/tangle-network/gadget/compare/gadget-blueprint-proc-macro-v0.3.0...gadget-blueprint-proc-macro-v0.3.1) - 2024-11-08

### Added

- constructors for Tangle and EVM ([#447](https://github.com/tangle-network/gadget/pull/447))

### Fixed

- handle edge cases during registration ([#452](https://github.com/tangle-network/gadget/pull/452))

## [0.3.0](https://github.com/tangle-network/gadget/compare/gadget-blueprint-proc-macro-v0.2.3...gadget-blueprint-proc-macro-v0.3.0) - 2024-11-05

### Added

- [**breaking**] Refactor EventFlows for EVM and Remove EventWatchers ([#423](https://github.com/tangle-network/gadget/pull/423))
- symbiotic initial integration ([#411](https://github.com/tangle-network/gadget/pull/411))

### Fixed

- *(gadget-sdk)* update sdk and utilities for tangle avs ([#355](https://github.com/tangle-network/gadget/pull/355))
- *(blueprint-proc-macro)* resolve dependency cycle with gadget-sdk
- *(cargo-tangle)* CLI bugs ([#409](https://github.com/tangle-network/gadget/pull/409))

### Other

- Continue Improving Event Flows ([#399](https://github.com/tangle-network/gadget/pull/399))

## [0.2.3](https://github.com/tangle-network/gadget/compare/gadget-blueprint-proc-macro-v0.2.2...gadget-blueprint-proc-macro-v0.2.3) - 2024-10-25

### Other

- updated the following local packages: gadget-blueprint-proc-macro-core, gadget-sdk

## [0.2.2](https://github.com/tangle-network/gadget/compare/gadget-blueprint-proc-macro-v0.2.1...gadget-blueprint-proc-macro-v0.2.2) - 2024-10-24

### Other

- Fix bug with tangle contexts ([#391](https://github.com/tangle-network/gadget/pull/391))

## [0.2.1](https://github.com/tangle-network/gadget/compare/gadget-blueprint-proc-macro-v0.2.0...gadget-blueprint-proc-macro-v0.2.1) - 2024-10-24

### Other

- Event Flows for Tangle ([#363](https://github.com/tangle-network/gadget/pull/363))

## [0.2.0](https://github.com/tangle-network/gadget/compare/gadget-blueprint-proc-macro-v0.1.2...gadget-blueprint-proc-macro-v0.2.0) - 2024-10-23

### Added

- eigenlayer incredible squaring blueprint and test ([#312](https://github.com/tangle-network/gadget/pull/312))

### Fixed

- *(sdk)* [**breaking**] downgrade substrate dependencies for now

### Other

- Fix eigenlayer example ([#375](https://github.com/tangle-network/gadget/pull/375))
- update to latest changes in tangle ([#367](https://github.com/tangle-network/gadget/pull/367))
- Event Workflows (phase 1: Custom listeners) ([#359](https://github.com/tangle-network/gadget/pull/359))
- Multi job runner + SDK main macro ([#346](https://github.com/tangle-network/gadget/pull/346))
- Event Listener Upgrade + Wrapper Types + sdk::main macro ([#333](https://github.com/tangle-network/gadget/pull/333))
- update naming ([#343](https://github.com/tangle-network/gadget/pull/343))
- docs fix spelling issues ([#336](https://github.com/tangle-network/gadget/pull/336))
- Event listener ([#317](https://github.com/tangle-network/gadget/pull/317))
- Return output from cmd exec ([#328](https://github.com/tangle-network/gadget/pull/328))

## [0.1.2](https://github.com/tangle-network/gadget/compare/gadget-blueprint-proc-macro-v0.1.1...gadget-blueprint-proc-macro-v0.1.2) - 2024-09-24

### Other

- Remove Logger ([#311](https://github.com/tangle-network/gadget/pull/311))
- Streamline keystore, cleanup testing, refactor blueprint manager, add tests, remove unnecessary code ([#285](https://github.com/tangle-network/gadget/pull/285))
