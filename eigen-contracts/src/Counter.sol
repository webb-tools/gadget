// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "eigenlayer-middleware/src/RegistryCoordinator.sol";
import "eigenlayer-middleware/src/OperatorStateRetriever.sol";
import "eigenlayer-middleware/src/StakeRegistry.sol";
import "eigenlayer-middleware/src/BLSApkRegistry.sol";
import "eigenlayer-middleware/src/interfaces/IBLSSignatureChecker.sol";
import "eigenlayer-middleware/src/ServiceManagerBase.sol";
import "eigenlayer-middleware/src/interfaces/IRegistryCoordinator.sol";
import "eigenlayer-contracts/src/contracts/core/DelegationManager.sol";
import "eigenlayer-contracts/src/contracts/interfaces/ISlasher.sol";
import "eigenlayer-contracts/src/contracts/core/StrategyManager.sol";
import "eigenlayer-contracts/src/contracts/pods/EigenPod.sol";
import "eigenlayer-contracts/src/contracts/pods/EigenPodManager.sol";
import "eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import "eigenlayer-contracts/src/contracts/core/AVSDirectory.sol";

contract Counter {
    uint256 public number;

    function setNumber(uint256 newNumber) public {
        number = newNumber;
    }

    function increment() public {
        number++;
    }
}
