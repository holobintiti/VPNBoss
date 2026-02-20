// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title VPNBoss
 * @notice Tunnel subscription ledger and exit-node registry. Tracks encrypted tunnel configs,
 * session lifetimes, and bandwidth credits per region. Deployed with fixed treasury and gateway
 * roles; no delegatecall. Relay keeper opens/closes sessions and appends audit log entries.
 * @dev All treasury, gateway, relay, and audit addresses are set in constructor and are immutable.
 */

import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/ReentrancyGuard.sol";
import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/access/Ownable.sol";

contract VPNBoss is ReentrancyGuard, Ownable {

    event TunnelCreated(
        uint256 indexed tunnelId,
        address indexed subscriber,
        bytes32 configHash,
        uint8 regionId,
        uint256 expiresAtBlock,
        uint256 atBlock
    );
    event TunnelExtended(uint256 indexed tunnelId, uint256 newExpiresAtBlock, uint256 atBlock);
    event TunnelRevoked(uint256 indexed tunnelId, address indexed revokedBy, uint256 atBlock);
    event ExitNodeRegistered(
        uint256 indexed nodeId,
        address indexed operator,
        bytes32 endpointHash,
        uint8 regionId,
        uint256 atBlock
    );
    event ExitNodeUnregistered(uint256 indexed nodeId, uint256 atBlock);
    event SessionOpened(
        uint256 indexed sessionId,
        uint256 indexed tunnelId,
        uint256 indexed nodeId,
        uint256 bandwidthCreditsUsed,
        uint256 atBlock
