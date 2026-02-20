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
    uint256 public constant VBN_MAX_FEE_BPS = 500;
    uint256 public constant VBN_MAX_TUNNELS_PER_USER = 32;
    uint256 public constant VBN_MAX_NODES_PER_REGION = 64;
    uint256 public constant VBN_MAX_EXTEND_BLOCKS = 500000;
    uint256 public constant VBN_MIN_EXTEND_BLOCKS = 1;
    uint256 public constant VBN_TUNNEL_SEED = 0x5a7c9e1b3d5f7a9c1e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8;
    uint8 public constant VBN_AUDIT_TYPE_SESSION_OPEN = 1;
    uint8 public constant VBN_AUDIT_TYPE_SESSION_CLOSE = 2;
    uint8 public constant VBN_AUDIT_TYPE_TUNNEL_CREATE = 3;
    uint8 public constant VBN_AUDIT_TYPE_NODE_REGISTER = 4;

    address public immutable vbnTreasury;
    address public immutable gatewayKeeper;
    address public immutable relayKeeper;
    address public immutable auditVault;
    uint256 public immutable genesisBlock;
    bytes32 public immutable chainNonce;

    address public relayKeeperRole;
    bool public gatewayPaused;
    uint256 public tunnelCounter;
    uint256 public nodeCounter;
    uint256 public sessionCounter;

    struct TunnelConfig {
        address subscriber;
        bytes32 configHash;
        uint8 regionId;
        uint256 expiresAtBlock;
        uint256 bandwidthCreditsWei;
        uint256 createdAtBlock;
        bool revoked;
    }

    struct ExitNodeRecord {
        address operator;
        bytes32 endpointHash;
        uint8 regionId;
        uint256 registeredAtBlock;
        bool active;
    }

    struct SessionRecord {
        uint256 tunnelId;
        uint256 nodeId;
        uint256 openedAtBlock;
        uint256 bandwidthCreditsUsed;
        uint256 totalBytesLogged;
        bool closed;
    }

    struct RegionSlot {
        uint256 maxNodes;
        uint256 feeBps;
        uint256 nodeCount;
        bool configured;
    }

    struct TunnelMetadata {
        bytes32 labelHash;
        uint256 lastUsedAtBlock;
        uint256 totalSessionsCount;
    }

    struct NodeStats {
        uint256 sessionsServed;
        uint256 totalBytesRelayed;
        uint256 lastActivityBlock;
    }

    struct AuditLogEntry {
        uint8 entryType;
        uint256 refId;
        address actor;
        uint256 atBlock;
        bytes32 extraHash;
    }

    struct SubscriptionTier {
        uint256 maxTunnels;
        uint256 minStakeWei;
        bool active;
    }

    mapping(uint256 => TunnelConfig) public tunnelConfigs;
    mapping(uint256 => TunnelMetadata) public tunnelMetadata;
    mapping(address => uint256[]) public tunnelIdsBySubscriber;
    mapping(uint256 => ExitNodeRecord) public exitNodes;
    mapping(uint8 => uint256[]) public nodeIdsByRegion;
    mapping(uint256 => SessionRecord) public sessionRecords;
    mapping(uint256 => uint256[]) public sessionIdsByTunnel;
    mapping(uint256 => uint256[]) public sessionIdsByNode;
    mapping(uint8 => RegionSlot) public regionSlots;
    mapping(address => uint256) public pendingTreasuryWei;
    mapping(uint256 => NodeStats) public nodeStats;
    mapping(uint8 => SubscriptionTier) public subscriptionTiers;
    mapping(address => uint8) public subscriberTier;
    AuditLogEntry[] private _auditLog;
    mapping(uint8 => uint256[]) private _tunnelIdsByRegion;

    uint256[] private _allTunnelIds;
    uint256[] private _allNodeIds;
    uint256[] private _allSessionIds;

    modifier whenNotPaused() {
        if (gatewayPaused) revert VBN_GatewayPaused();
        _;
    }

    modifier onlyRelayKeeper() {
        if (msg.sender != relayKeeperRole) revert VBN_NotRelayKeeper();
        _;
    }

    constructor() {
        vbnTreasury = address(0xA7f2C4e6B8d0E1a3F5c7D9e1B3d5F7a9C1e4A6);
        gatewayKeeper = address(0xB8e3D5f7A9c1E4b6D8f0A2c4E6b8D0f2A4c6);
        relayKeeper = address(0xC9f4E6a8B0d2F4b6C8e0A2d4F6b8C0e2A4c6);
        auditVault = address(0xD0a5F7b9C1e3D5f7A9b1C3e5D7f9A1b3C5d7);
        relayKeeperRole = address(0xE1b6A8c0D2e4F6a8B0c2D4e6F8a0B2c4D6e8);
        genesisBlock = block.number;
        chainNonce = keccak256(abi.encodePacked("VPNBoss_", block.chainid, block.timestamp, address(this)));
    }

    function setGatewayPaused(bool paused) external onlyOwner {
        gatewayPaused = paused;
        emit GatewayPauseToggled(paused);
    }

    function setRelayKeeper(address newKeeper) external onlyOwner {
        if (newKeeper == address(0)) revert VBN_ZeroAddress();
        address prev = relayKeeperRole;
        relayKeeperRole = newKeeper;
        emit RelayKeeperUpdated(prev, newKeeper);
    }

    function setSubscriptionTier(uint8 tierId, uint256 maxTunnels, uint256 minStakeWei) external onlyOwner {
        if (tierId >= VBN_MAX_TIERS) revert VBN_RegionInvalid();
        subscriptionTiers[tierId] = SubscriptionTier({
            maxTunnels: maxTunnels,
            minStakeWei: minStakeWei,
            active: true
        });
        emit SubscriptionTierSet(tierId, maxTunnels, minStakeWei, block.number);
    }

    function setSubscriberTier(address subscriber, uint8 tierId) external onlyOwner {
        if (subscriber == address(0)) revert VBN_ZeroAddress();
        if (tierId >= VBN_MAX_TIERS && tierId != 0) revert VBN_RegionInvalid();
        subscriberTier[subscriber] = tierId;
        emit SubscriberTierAssigned(subscriber, tierId, block.number);
    }

    function deactivateSubscriptionTier(uint8 tierId) external onlyOwner {
        if (tierId >= VBN_MAX_TIERS) revert VBN_RegionInvalid();
        subscriptionTiers[tierId].active = false;
        emit SubscriptionTierDeactivated(tierId, block.number);
    }

    function updateTunnelMetadata(uint256 tunnelId, bytes32 labelHash) external whenNotPaused {
        TunnelConfig storage tc = tunnelConfigs[tunnelId];
        if (tc.createdAtBlock == 0) revert VBN_TunnelNotFound();
        if (tc.subscriber != msg.sender) revert VBN_TunnelNotOwner();
        if (tc.revoked) revert VBN_TunnelNotFound();
        tunnelMetadata[tunnelId].labelHash = labelHash;
        emit TunnelMetadataUpdated(tunnelId, labelHash, block.number);
    }

    function appendAuditLog(uint8 entryType, uint256 refId, bytes32 extraHash) external onlyRelayKeeper {
        _auditLog.push(AuditLogEntry({
            entryType: entryType,
            refId: refId,
            actor: msg.sender,
            atBlock: block.number,
            extraHash: extraHash
        }));
        emit AuditLogAppended(_auditLog.length - 1, entryType, refId, block.number);
    }

    function _effectiveMaxTunnels(address subscriber) internal view returns (uint256) {
        uint8 tier = subscriberTier[subscriber];
        SubscriptionTier storage st = subscriptionTiers[tier];
        if (st.active && st.maxTunnels > 0) return st.maxTunnels;
        return VBN_MAX_TUNNELS_PER_USER;
    }

    function _validateTunnelActive(uint256 tunnelId) internal view returns (TunnelConfig storage tc) {
        tc = tunnelConfigs[tunnelId];
        if (tc.createdAtBlock == 0) revert VBN_TunnelNotFound();
        if (tc.revoked || block.number >= tc.expiresAtBlock) revert VBN_TunnelExpired();
    }

    function _validateNodeActiveForRegion(uint256 nodeId, uint8 regionId) internal view returns (ExitNodeRecord storage en) {
        en = exitNodes[nodeId];
        if (en.registeredAtBlock == 0 || !en.active) revert VBN_NodeNotFound();
        if (en.regionId != regionId) revert VBN_RegionInvalid();
    }

    /// @param regionId Region identifier (0 to 255).
    /// @param maxNodes Maximum exit nodes allowed in this region.
