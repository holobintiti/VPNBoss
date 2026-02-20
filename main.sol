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
    );
    event SessionClosed(uint256 indexed sessionId, uint256 totalBytesLogged, uint256 atBlock);
    event BandwidthCreditsDeposited(address indexed subscriber, uint256 tunnelId, uint256 amountWei, uint256 atBlock);
    event BandwidthCreditsConsumed(uint256 indexed tunnelId, uint256 amount, uint256 atBlock);
    event RegionSlotUpdated(uint8 regionId, uint256 maxNodes, uint256 feeBps, uint256 atBlock);
    event GatewayPauseToggled(bool paused);
    event TreasurySweep(address indexed to, uint256 amountWei, uint256 atBlock);
    event RelayKeeperUpdated(address indexed previousKeeper, address indexed newKeeper);
    event TunnelMetadataUpdated(uint256 indexed tunnelId, bytes32 labelHash, uint256 atBlock);
    event AuditLogAppended(uint256 indexed logIndex, uint8 entryType, uint256 refId, uint256 atBlock);
    event SubscriptionTierSet(uint8 tierId, uint256 maxTunnels, uint256 minStakeWei, uint256 atBlock);
    event SubscriberTierAssigned(address indexed subscriber, uint8 tierId, uint256 atBlock);
    event SubscriptionTierDeactivated(uint8 tierId, uint256 atBlock);

    error VBN_ZeroAddress();
    error VBN_ZeroAmount();
    error VBN_GatewayPaused();
    error VBN_TunnelNotFound();
    error VBN_TunnelExpired();
    error VBN_TunnelNotOwner();
    error VBN_NodeNotFound();
    error VBN_NodeNotOperator();
    error VBN_NodeInactive();
    error VBN_SessionNotFound();
    error VBN_SessionAlreadyClosed();
    error VBN_RegionInvalid();
    error VBN_RegionSlotFull();
    error VBN_InsufficientCredits();
    error VBN_TransferFailed();
    error VBN_ConfigHashZero();
    error VBN_MaxTunnelsPerUser();
    error VBN_MaxNodesPerRegion();
    error VBN_ExpiryTooFar();
    error VBN_ExpiryPast();
    error VBN_Reentrancy();
    error VBN_NotRelayKeeper();
    error VBN_TierLimit();

    uint256 public constant VBN_BPS_DENOM = 10000;
    uint256 public constant VBN_MAX_TIERS = 8;
