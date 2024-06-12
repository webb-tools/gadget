// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "eigenlayer-contracts/src/contracts/permissions/Pausable.sol";
import "eigenlayer-middleware/src/interfaces/IServiceManager.sol";
import {BLSApkRegistry} from "eigenlayer-middleware/src/BLSApkRegistry.sol";
import {RegistryCoordinator} from "eigenlayer-middleware/src/RegistryCoordinator.sol";
import {BLSSignatureChecker, IRegistryCoordinator} from "eigenlayer-middleware/src/BLSSignatureChecker.sol";
import {OperatorStateRetriever} from "eigenlayer-middleware/src/OperatorStateRetriever.sol";
import "eigenlayer-middleware/src/libraries/BN254.sol";
import "./ITangleValidatorTaskManager.sol";

contract TangleValidatorTaskManager is
    Initializable,
    OwnableUpgradeable,
    Pausable,
    OperatorStateRetriever,
    ITangleValidatorTaskManager
{
    constructor(
        IRegistryCoordinator _registryCoordinator
    ) {}

    function initialize(
        IPauserRegistry _pauserRegistry,
        address initialOwner
    ) public initializer {
        _initializePauser(_pauserRegistry, UNPAUSE_ALL);
        _transferOwnership(initialOwner);
    }

    function reportSlashingEvent(
        TangleSlashingEvent calldata slashingEvent
    ) external override onlyPauser {
        // if (
        //     IServiceManager(
        //         address(
        //             BLSRegistryCoordinatorWithIndices(
        //                 address(registryCoordinator)
        //             ).serviceManager()
        //         )
        //     ).slasher().isFrozen(operatorAddress) == false
        // ) {
        //     // TODO: Verify the slashing event
        //     BLSRegistryCoordinatorWithIndices(
        //         address(registryCoordinator)
        //     ).serviceManager().freezeOperator(operatorAddress);
        // }
    }
}
