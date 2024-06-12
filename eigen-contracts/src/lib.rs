use alloy_sol_types::sol;

sol!(
    #[allow(missing_docs)]
    #[derive(Debug)]
    #[sol(rpc)]
    BlsApkRegistry,
    "out/BLSApkRegistry.sol/BLSApkRegistry.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ServiceManagerBase,
    "out/ServiceManagerBase.sol/ServiceManagerBase.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    StakeRegistry,
    "out/StakeRegistry.sol/StakeRegistry.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    RegistryCoordinator,
    "out/RegistryCoordinator.sol/RegistryCoordinator.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OperatorStateRetriever,
    "out/OperatorStateRetriever.sol/OperatorStateRetriever.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    AVSDirectory,
    "out/AVSDirectory.sol/AVSDirectory.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    DelegationManager,
    "out/DelegationManager.sol/DelegationManager.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ISlasher,
    "out/ISlasher.sol/ISlasher.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IStrategy,
    "out/IStrategy.sol/IStrategy.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IERC20,
    "out/IERC20.sol/IERC20.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    StrategyManager,
    "out/StrategyManager.sol/StrategyManager.json"
);
