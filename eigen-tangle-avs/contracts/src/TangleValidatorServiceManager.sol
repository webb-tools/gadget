// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "eigenlayer-contracts/src/contracts/libraries/BytesLib.sol";
import "./ITangleValidatorTaskManager.sol";
import "eigenlayer-middleware/src/ServiceManagerBase.sol";

/**
 * @title Primary entrypoint for procuring services from TangleValidator.
 * @author Tangle Foundation
 */
contract TangleValidatorServiceManager is ServiceManagerBase {
    using BytesLib for bytes;

    ITangleValidatorTaskManager
        public immutable TangleValidatorOperatorManager;

    /// @notice when applied to a function, ensures that the function is only callable by the `registryCoordinator`.
    modifier onlyTangleValidatorOperatorManager() {
        require(
            msg.sender == address(TangleValidatorOperatorManager),
            "onlyTangleValidatorOperatorManager: not from credible squaring task manager"
        );
        _;
    }

    constructor(
        IAVSDirectory _avsDirectory,
        IRegistryCoordinator _registryCoordinator,
        IStakeRegistry _stakeRegistry,
        ITangleValidatorTaskManager _TangleValidatorOperatorManager
    )
        ServiceManagerBase(
            _avsDirectory,
            IRewardsCoordinator(address(0)), // inc-sq doesn't need to deal with payments
            _registryCoordinator,
            _stakeRegistry
        )
    {
        TangleValidatorOperatorManager = _TangleValidatorOperatorManager;
    }

    /// @notice Called in the event of a slashing event from the Tangle.
    function slash(
        address operatorAddr
    ) external onlyTangleValidatorOperatorManager {
        // slasher.freezeOperator(operatorAddr);
    }
}
