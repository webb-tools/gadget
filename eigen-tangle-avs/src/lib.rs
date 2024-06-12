use alloy_sol_types::sol;

pub mod operator;

sol!(
    #[allow(missing_docs)]
    #[derive(Debug)]
    #[sol(rpc)]
    TangleValidatorTaskManager,
    "contracts/out/TangleValidatorTaskManager.sol/TangleValidatorTaskManager.json"
);

sol!(
    #[allow(missing_docs)]
    #[derive(Debug)]
    #[sol(rpc)]
    TangleValidatorServiceManager,
    "contracts/out/TangleValidatorServiceManager.sol/TangleValidatorServiceManager.json"
);
