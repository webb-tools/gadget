// This file is part of Tangle.
// Copyright (C) 2022-2023 Webb Technologies Inc.
//
// Tangle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Tangle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Tangle.  If not, see <http://www.gnu.org/licenses/>.

#![allow(clippy::async_yields_async)]

use gadget_sdk::config::{ContextConfig, GadgetConfiguration};
use gadget_sdk::runners::{BlueprintConfig, BlueprintRunner, RunnerError};
use gadget_sdk::{error, info};
use std::future::Future;
use std::path::PathBuf;
use tokio::task::JoinHandle;

pub const NAME_IDS: [&str; 5] = ["Alice", "Bob", "Charlie", "Dave", "Eve"];

/// Configuration for the test runner
#[derive(Clone)]
pub struct TestRunnerConfig {
    /// Number of nodes to run (max 5)
    pub num_nodes: usize,
    /// Base path for node keystores
    pub keystore_path: PathBuf,
    /// Protocol-specific configuration
    pub context_config: ContextConfig,
}

impl Default for TestRunnerConfig {
    fn default() -> Self {
        Self {
            num_nodes: 1,
            keystore_path: PathBuf::from("test-keystores"),
            context_config: ContextConfig::default(),
        }
    }
}

/// Test runner environment that manages multiple BlueprintRunners
pub struct TestRunnerExt {
    runners: Vec<BlueprintRunner>,
    config: TestRunnerConfig,
    handles: Vec<JoinHandle<Result<(), RunnerError>>>,
}

impl TestRunnerExt {
    /// Create a new test runner with the given configuration
    pub fn new<C: Into<TestRunnerConfig>>(config: C) -> Self {
        let config = config.into();
        assert!(
            config.num_nodes <= NAME_IDS.len(),
            "Only up to 5 nodes are supported"
        );
        assert!(config.num_nodes > 0, "At least one node is required");

        Self {
            runners: Vec::new(),
            config,
            handles: Vec::new(),
        }
    }

    /// Initialize the test environment with the given blueprint configuration
    pub async fn initialize<BC: BlueprintConfig + Clone>(
        &mut self,
        blueprint_config: BC,
    ) -> Result<(), RunnerError> {
        let mut handles = Vec::new();

        // Initialize and start each node
        for i in 0..self.config.num_nodes {
            info!("Initializing runner {}", NAME_IDS[i]);
            let env = gadget_sdk::config::load(self.config.context_config.clone())?;

            // Create and configure BlueprintRunner
            let mut runner = BlueprintRunner::new(blueprint_config.clone(), env.clone());

            info!("Starting runner {}", NAME_IDS[i]);
            let handle = tokio::spawn(async move { runner.run().await });
            handles.push(handle);

            // Create another runner instance for interaction
            let interact_runner = BlueprintRunner::new(blueprint_config.clone(), env);
            self.runners.push(interact_runner);
        }

        self.handles = handles;
        Ok(())
    }

    /// Execute a function with the test environment
    pub fn execute_with<T, R>(&self, function: T) -> R
    where
        T: FnOnce(&[BlueprintRunner]) -> R,
    {
        function(&self.runners)
    }

    /// Execute an async function with the test environment
    pub async fn execute_with_async<'a, T, Fut, R>(&'a self, function: T) -> R
    where
        T: FnOnce(&'a [BlueprintRunner]) -> Fut,
        Fut: Future<Output = R> + 'a,
    {
        function(&self.runners).await
    }

    /// Wait for all runners to complete
    pub async fn wait_for_completion(self) -> Result<(), RunnerError> {
        for (i, handle) in self.handles.into_iter().enumerate() {
            if let Err(e) = handle
                .await
                .map_err(|e| RunnerError::TransactionError(e.to_string()))?
            {
                error!("Runner {} failed: {:?}", NAME_IDS[i], e);
                return Err(e);
            }
        }
        Ok(())
    }
}

/// Create a new test runner with default configuration and initialize it with the given blueprint config
pub async fn new_test_runner<BC: BlueprintConfig + Clone>(
    blueprint_config: BC,
    num_nodes: usize,
) -> Result<TestRunnerExt, RunnerError> {
    let config = TestRunnerConfig {
        num_nodes,
        ..Default::default()
    };

    let mut runner = TestRunnerExt::new(config);
    runner.initialize(blueprint_config).await?;
    Ok(runner)
}
