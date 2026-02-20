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
    /// @param feeBps Fee in basis points (of tunnel creation payment) sent to treasury; max VBN_MAX_FEE_BPS.
    function configureRegion(uint8 regionId, uint256 maxNodes, uint256 feeBps) external onlyOwner {
        if (feeBps > VBN_MAX_FEE_BPS) revert VBN_RegionInvalid();
        regionSlots[regionId] = RegionSlot({
            maxNodes: maxNodes,
            feeBps: feeBps,
            nodeCount: regionSlots[regionId].nodeCount,
            configured: true
        });
        emit RegionSlotUpdated(regionId, maxNodes, feeBps, block.number);
    }

    /// @param configHash Keccak256 of tunnel config (e.g. from computeConfigHash).
    /// @param regionId Region slot id; region must be configured via configureRegion.
    /// @param expiryBlocksFromNow Tunnel validity duration in blocks; capped by VBN_MAX_EXTEND_BLOCKS.
    /// @return tunnelId Id of the created tunnel.
    function createTunnel(
        bytes32 configHash,
        uint8 regionId,
        uint256 expiryBlocksFromNow
    ) external payable whenNotPaused nonReentrant returns (uint256 tunnelId) {
        if (msg.sender == address(0)) revert VBN_ZeroAddress();
        if (configHash == bytes32(0)) revert VBN_ConfigHashZero();
        if (expiryBlocksFromNow == 0 || expiryBlocksFromNow > VBN_MAX_EXTEND_BLOCKS) revert VBN_ExpiryTooFar();
        if (!regionSlots[regionId].configured) revert VBN_RegionInvalid();
        uint256 maxTunnels = _effectiveMaxTunnels(msg.sender);
        if (tunnelIdsBySubscriber[msg.sender].length >= maxTunnels) revert VBN_TierLimit();

        tunnelCounter++;
        tunnelId = tunnelCounter;
        uint256 expiresAt = block.number + expiryBlocksFromNow;

        tunnelConfigs[tunnelId] = TunnelConfig({
            subscriber: msg.sender,
            configHash: configHash,
            regionId: regionId,
            expiresAtBlock: expiresAt,
            bandwidthCreditsWei: msg.value,
            createdAtBlock: block.number,
            revoked: false
        });
        tunnelIdsBySubscriber[msg.sender].push(tunnelId);
        _allTunnelIds.push(tunnelId);
        _tunnelIdsByRegion[regionId].push(tunnelId);
        tunnelMetadata[tunnelId] = TunnelMetadata({
            labelHash: bytes32(0),
            lastUsedAtBlock: 0,
            totalSessionsCount: 0
        });

        uint256 feeWei = 0;
        if (regionSlots[regionId].feeBps > 0 && msg.value > 0) {
            feeWei = (msg.value * regionSlots[regionId].feeBps) / VBN_BPS_DENOM;
            pendingTreasuryWei[vbnTreasury] += feeWei;
            tunnelConfigs[tunnelId].bandwidthCreditsWei = msg.value - feeWei;
        }

        emit TunnelCreated(tunnelId, msg.sender, configHash, regionId, expiresAt, block.number);
        return tunnelId;
    }

    /// @param tunnelId Tunnel to extend.
    /// @param additionalBlocks Blocks to add to current expiry; capped by VBN_MAX_EXTEND_BLOCKS.
    function extendTunnel(uint256 tunnelId, uint256 additionalBlocks) external whenNotPaused nonReentrant {
        TunnelConfig storage tc = tunnelConfigs[tunnelId];
        if (tc.createdAtBlock == 0) revert VBN_TunnelNotFound();
        if (tc.subscriber != msg.sender) revert VBN_TunnelNotOwner();
        if (tc.revoked) revert VBN_TunnelNotFound();
        if (block.number >= tc.expiresAtBlock) revert VBN_TunnelExpired();
        if (additionalBlocks == 0 || additionalBlocks > VBN_MAX_EXTEND_BLOCKS) revert VBN_ExpiryTooFar();

        tc.expiresAtBlock += additionalBlocks;
        emit TunnelExtended(tunnelId, tc.expiresAtBlock, block.number);
    }

    /// @param tunnelId Tunnel to revoke; remaining bandwidth credits are refunded to subscriber.
    function revokeTunnel(uint256 tunnelId) external whenNotPaused nonReentrant {
        TunnelConfig storage tc = tunnelConfigs[tunnelId];
        if (tc.createdAtBlock == 0) revert VBN_TunnelNotFound();
        if (tc.subscriber != msg.sender && msg.sender != owner()) revert VBN_TunnelNotOwner();
        if (tc.revoked) revert VBN_TunnelNotFound();

        tc.revoked = true;
        uint256 refund = tc.bandwidthCreditsWei;
        tc.bandwidthCreditsWei = 0;
        if (refund > 0) {
            (bool sent,) = tc.subscriber.call{value: refund}("");
            if (!sent) revert VBN_TransferFailed();
        }
        emit TunnelRevoked(tunnelId, msg.sender, block.number);
    }

    /// @param tunnelId Tunnel to credit; must be active and owned by caller.
    /// @dev Sends msg.value to tunnel's bandwidthCreditsWei; no fee applied on deposit.
    function depositBandwidthCredits(uint256 tunnelId) external payable whenNotPaused nonReentrant {
        TunnelConfig storage tc = tunnelConfigs[tunnelId];
        if (tc.createdAtBlock == 0) revert VBN_TunnelNotFound();
        if (tc.subscriber != msg.sender) revert VBN_TunnelNotOwner();
        if (tc.revoked || block.number >= tc.expiresAtBlock) revert VBN_TunnelExpired();
        if (msg.value == 0) revert VBN_ZeroAmount();

        tc.bandwidthCreditsWei += msg.value;
        emit BandwidthCreditsDeposited(msg.sender, tunnelId, msg.value, block.number);
    }

    /// @param endpointHash Keccak256 of node endpoint descriptor.
    /// @param regionId Region slot; must be configured and not full.
    /// @return nodeId Id of the registered exit node.
    function registerExitNode(
        bytes32 endpointHash,
        uint8 regionId
    ) external whenNotPaused nonReentrant returns (uint256 nodeId) {
        if (msg.sender == address(0)) revert VBN_ZeroAddress();
        if (endpointHash == bytes32(0)) revert VBN_ConfigHashZero();
        if (!regionSlots[regionId].configured) revert VBN_RegionInvalid();
        RegionSlot storage rs = regionSlots[regionId];
        if (rs.nodeCount >= rs.maxNodes) revert VBN_RegionSlotFull();

        nodeCounter++;
        nodeId = nodeCounter;
        exitNodes[nodeId] = ExitNodeRecord({
            operator: msg.sender,
            endpointHash: endpointHash,
            regionId: regionId,
            registeredAtBlock: block.number,
            active: true
        });
        nodeIdsByRegion[regionId].push(nodeId);
        rs.nodeCount++;
        _allNodeIds.push(nodeId);
        emit ExitNodeRegistered(nodeId, msg.sender, endpointHash, regionId, block.number);
        return nodeId;
    }

    function unregisterExitNode(uint256 nodeId) external whenNotPaused nonReentrant {
        ExitNodeRecord storage en = exitNodes[nodeId];
        if (en.registeredAtBlock == 0) revert VBN_NodeNotFound();
        if (en.operator != msg.sender && msg.sender != owner()) revert VBN_NodeNotOperator();
        if (!en.active) revert VBN_NodeInactive();

        en.active = false;
        regionSlots[en.regionId].nodeCount--;
        emit ExitNodeUnregistered(nodeId, block.number);
    }

    /// @param tunnelId Active tunnel for the session.
    /// @param nodeId Active exit node in same region as tunnel.
    /// @param bandwidthCreditsToReserve Wei to reserve from tunnel for this session.
    /// @return sessionId Id of the opened session.
    function openSession(
        uint256 tunnelId,
        uint256 nodeId,
        uint256 bandwidthCreditsToReserve
    ) external onlyRelayKeeper whenNotPaused nonReentrant returns (uint256 sessionId) {
        TunnelConfig storage tc = _validateTunnelActive(tunnelId);
        ExitNodeRecord storage en = _validateNodeActiveForRegion(nodeId, tc.regionId);
        if (bandwidthCreditsToReserve > tc.bandwidthCreditsWei) revert VBN_InsufficientCredits();

        tc.bandwidthCreditsWei -= bandwidthCreditsToReserve;
        sessionCounter++;
        sessionId = sessionCounter;
        sessionRecords[sessionId] = SessionRecord({
            tunnelId: tunnelId,
            nodeId: nodeId,
            openedAtBlock: block.number,
            bandwidthCreditsUsed: bandwidthCreditsToReserve,
            totalBytesLogged: 0,
            closed: false
        });
        sessionIdsByTunnel[tunnelId].push(sessionId);
        sessionIdsByNode[nodeId].push(sessionId);
        _allSessionIds.push(sessionId);

        emit SessionOpened(sessionId, tunnelId, nodeId, bandwidthCreditsToReserve, block.number);
        emit BandwidthCreditsConsumed(tunnelId, bandwidthCreditsToReserve, block.number);
        return sessionId;
    }

    /// @param sessionId Session to close.
    /// @param totalBytesLogged Total bytes relayed in this session; stored for node stats.
    function closeSession(uint256 sessionId, uint256 totalBytesLogged) external onlyRelayKeeper whenNotPaused nonReentrant {
        SessionRecord storage sr = sessionRecords[sessionId];
        if (sr.openedAtBlock == 0) revert VBN_SessionNotFound();
        if (sr.closed) revert VBN_SessionAlreadyClosed();

        sr.closed = true;
        sr.totalBytesLogged = totalBytesLogged;

        tunnelMetadata[sr.tunnelId].lastUsedAtBlock = block.number;
        tunnelMetadata[sr.tunnelId].totalSessionsCount++;

        NodeStats storage ns = nodeStats[sr.nodeId];
        ns.sessionsServed++;
        ns.totalBytesRelayed += totalBytesLogged;
        ns.lastActivityBlock = block.number;

        emit SessionClosed(sessionId, totalBytesLogged, block.number);
    }

    /// @dev Sends accumulated pendingTreasuryWei[vbnTreasury] to vbnTreasury. Callable by owner or vbnTreasury.
    function sweepTreasury() external nonReentrant {
        if (msg.sender != owner() && msg.sender != vbnTreasury) revert VBN_ZeroAddress();
        uint256 amount = pendingTreasuryWei[vbnTreasury];
        if (amount == 0) revert VBN_ZeroAmount();
        pendingTreasuryWei[vbnTreasury] = 0;
        (bool sent,) = vbnTreasury.call{value: amount}("");
        if (!sent) revert VBN_TransferFailed();
        emit TreasurySweep(vbnTreasury, amount, block.number);
    }

    /// @param tunnelId Tunnel id.
    /// @return subscriber Owner of the tunnel.
    /// @return configHash Stored config hash.
    /// @return regionId Region slot id.
    /// @return expiresAtBlock Block after which tunnel is expired.
    /// @return bandwidthCreditsWei Remaining bandwidth credits (wei).
    /// @return createdAtBlock Block at creation.
    /// @return revoked Whether tunnel was revoked.
    function getTunnelConfig(uint256 tunnelId) external view returns (
        address subscriber,
        bytes32 configHash,
        uint8 regionId,
        uint256 expiresAtBlock,
        uint256 bandwidthCreditsWei,
        uint256 createdAtBlock,
        bool revoked
    ) {
        TunnelConfig storage tc = tunnelConfigs[tunnelId];
        return (
            tc.subscriber,
            tc.configHash,
            tc.regionId,
            tc.expiresAtBlock,
            tc.bandwidthCreditsWei,
            tc.createdAtBlock,
            tc.revoked
        );
    }

    /// @param nodeId Exit node id.
    /// @return operator Address that registered the node.
    /// @return endpointHash Stored endpoint hash.
    /// @return regionId Region slot id.
    /// @return registeredAtBlock Block at registration.
    /// @return active Whether node is still active.
    function getExitNode(uint256 nodeId) external view returns (
        address operator,
        bytes32 endpointHash,
        uint8 regionId,
        uint256 registeredAtBlock,
        bool active
    ) {
        ExitNodeRecord storage en = exitNodes[nodeId];
        return (
            en.operator,
            en.endpointHash,
            en.regionId,
            en.registeredAtBlock,
            en.active
        );
    }

    /// @param sessionId Session id.
    /// @return tunnelId Tunnel used.
    /// @return nodeId Exit node used.
    /// @return openedAtBlock Block when session opened.
    /// @return bandwidthCreditsUsed Credits reserved for this session.
    /// @return totalBytesLogged Bytes relayed (set when closed).
    /// @return closed Whether session was closed.
    function getSession(uint256 sessionId) external view returns (
        uint256 tunnelId,
        uint256 nodeId,
        uint256 openedAtBlock,
        uint256 bandwidthCreditsUsed,
        uint256 totalBytesLogged,
        bool closed
    ) {
        SessionRecord storage sr = sessionRecords[sessionId];
        return (
            sr.tunnelId,
            sr.nodeId,
            sr.openedAtBlock,
            sr.bandwidthCreditsUsed,
            sr.totalBytesLogged,
            sr.closed
        );
    }

    /// @param regionId Region id.
    /// @return maxNodes Max nodes allowed in region.
    /// @return feeBps Fee in bps on tunnel creation.
    /// @return nodeCount Current number of registered nodes.
    /// @return configured Whether region was configured.
    function getRegionSlot(uint8 regionId) external view returns (
        uint256 maxNodes,
        uint256 feeBps,
        uint256 nodeCount,
        bool configured
    ) {
        RegionSlot storage rs = regionSlots[regionId];
        return (rs.maxNodes, rs.feeBps, rs.nodeCount, rs.configured);
    }

    function getTunnelIdsBySubscriber(address subscriber) external view returns (uint256[] memory) {
        return tunnelIdsBySubscriber[subscriber];
    }

    function getNodeIdsByRegion(uint8 regionId) external view returns (uint256[] memory) {
        return nodeIdsByRegion[regionId];
    }

    function getTunnelIdsByRegion(uint8 regionId) external view returns (uint256[] memory) {
        return _tunnelIdsByRegion[regionId];
    }

    function getSessionIdsByTunnel(uint256 tunnelId) external view returns (uint256[] memory) {
        return sessionIdsByTunnel[tunnelId];
    }

    function getSessionIdsByNode(uint256 nodeId) external view returns (uint256[] memory) {
        return sessionIdsByNode[nodeId];
    }

    function isTunnelActive(uint256 tunnelId) external view returns (bool) {
        TunnelConfig storage tc = tunnelConfigs[tunnelId];
        return tc.createdAtBlock != 0 && !tc.revoked && block.number < tc.expiresAtBlock;
    }

    function getAllTunnelIds() external view returns (uint256[] memory) {
        return _allTunnelIds;
    }

    function getAllNodeIds() external view returns (uint256[] memory) {
        return _allNodeIds;
    }

    function computeConfigHash(
        bytes32 secretHash,
        uint8 regionId,
        uint256 nonce
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(secretHash, regionId, nonce, VBN_TUNNEL_SEED));
    }

    function getTunnelFullView(uint256 tunnelId) external view returns (
        address subscriber,
        bytes32 configHash,
        uint8 regionId,
        uint256 expiresAtBlock,
        uint256 bandwidthCreditsWei,
        uint256 createdAtBlock,
        bool revoked,
        bytes32 labelHash,
        uint256 lastUsedAtBlock,
        uint256 totalSessionsCount
    ) {
        TunnelConfig storage tc = tunnelConfigs[tunnelId];
        TunnelMetadata storage tm = tunnelMetadata[tunnelId];
        return (
            tc.subscriber,
            tc.configHash,
            tc.regionId,
            tc.expiresAtBlock,
            tc.bandwidthCreditsWei,
            tc.createdAtBlock,
            tc.revoked,
            tm.labelHash,
            tm.lastUsedAtBlock,
            tm.totalSessionsCount
        );
    }

    /// @param tunnelIds Tunnel ids to query.
    /// @return subscribers Subscriber per tunnel.
    /// @return configHashes Config hash per tunnel.
    /// @return regionIds Region id per tunnel.
    /// @return expiresAtBlocks Expiry block per tunnel.
    /// @return bandwidthCreditsWei Credits per tunnel.
    /// @return createdAtBlocks Creation block per tunnel.
    /// @return revoked Revoked flag per tunnel.
    /// @return labelHashes Label hash per tunnel.
    /// @return lastUsedAtBlocks Last used block per tunnel.
    /// @return totalSessionsCounts Session count per tunnel.
    function getTunnelFullViewBatch(uint256[] calldata tunnelIds) external view returns (
        address[] memory subscribers,
        bytes32[] memory configHashes,
        uint8[] memory regionIds,
        uint256[] memory expiresAtBlocks,
        uint256[] memory bandwidthCreditsWei,
        uint256[] memory createdAtBlocks,
        bool[] memory revoked,
        bytes32[] memory labelHashes,
        uint256[] memory lastUsedAtBlocks,
        uint256[] memory totalSessionsCounts
    ) {
        uint256 n = tunnelIds.length;
        subscribers = new address[](n);
        configHashes = new bytes32[](n);
        regionIds = new uint8[](n);
        expiresAtBlocks = new uint256[](n);
        bandwidthCreditsWei = new uint256[](n);
        createdAtBlocks = new uint256[](n);
        revoked = new bool[](n);
        labelHashes = new bytes32[](n);
        lastUsedAtBlocks = new uint256[](n);
        totalSessionsCounts = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 tid = tunnelIds[i];
            TunnelConfig storage tc = tunnelConfigs[tid];
            TunnelMetadata storage tm = tunnelMetadata[tid];
            subscribers[i] = tc.subscriber;
            configHashes[i] = tc.configHash;
            regionIds[i] = tc.regionId;
            expiresAtBlocks[i] = tc.expiresAtBlock;
            bandwidthCreditsWei[i] = tc.bandwidthCreditsWei;
            createdAtBlocks[i] = tc.createdAtBlock;
            revoked[i] = tc.revoked;
            labelHashes[i] = tm.labelHash;
            lastUsedAtBlocks[i] = tm.lastUsedAtBlock;
            totalSessionsCounts[i] = tm.totalSessionsCount;
        }
    }

    /// @param nodeId Exit node id.
    /// @return operator Node operator address.
    /// @return endpointHash Endpoint hash.
    /// @return regionId Region id.
    /// @return registeredAtBlock Registration block.
    /// @return active Active flag.
    /// @return sessionsServed Total sessions served.
    /// @return totalBytesRelayed Total bytes relayed.
    /// @return lastActivityBlock Last activity block.
    function getNodeFullView(uint256 nodeId) external view returns (
        address operator,
        bytes32 endpointHash,
        uint8 regionId,
        uint256 registeredAtBlock,
        bool active,
        uint256 sessionsServed,
        uint256 totalBytesRelayed,
        uint256 lastActivityBlock
    ) {
        ExitNodeRecord storage en = exitNodes[nodeId];
        NodeStats storage ns = nodeStats[nodeId];
        return (
            en.operator,
            en.endpointHash,
            en.regionId,
            en.registeredAtBlock,
            en.active,
            ns.sessionsServed,
            ns.totalBytesRelayed,
            ns.lastActivityBlock
        );
    }

    function getConfigSnapshot() external view returns (
        address vbnTreasury_,
        address gatewayKeeper_,
        address relayKeeper_,
        address auditVault_,
        uint256 genesisBlock_,
        uint256 tunnelCounter_,
        uint256 nodeCounter_,
        uint256 sessionCounter_,
        bool gatewayPaused_
    ) {
        return (
            vbnTreasury,
            gatewayKeeper,
            relayKeeper,
            auditVault,
            genesisBlock,
            tunnelCounter,
            nodeCounter,
            sessionCounter,
            gatewayPaused
        );
    }

    function getTunnelMetadata(uint256 tunnelId) external view returns (
        bytes32 labelHash,
        uint256 lastUsedAtBlock,
        uint256 totalSessionsCount
    ) {
        TunnelMetadata storage tm = tunnelMetadata[tunnelId];
        return (tm.labelHash, tm.lastUsedAtBlock, tm.totalSessionsCount);
    }

    function getNodeStats(uint256 nodeId) external view returns (
        uint256 sessionsServed,
        uint256 totalBytesRelayed,
        uint256 lastActivityBlock
    ) {
        NodeStats storage ns = nodeStats[nodeId];
        return (ns.sessionsServed, ns.totalBytesRelayed, ns.lastActivityBlock);
    }

    function getAuditLogLength() external view returns (uint256) {
        return _auditLog.length;
    }

    function getAuditLogSlice(uint256 offset, uint256 limit) external view returns (
        uint8[] memory entryTypes,
        uint256[] memory refIds,
        address[] memory actors,
        uint256[] memory atBlocks,
        bytes32[] memory extraHashes
    ) {
        uint256 len = _auditLog.length;
        if (offset >= len) {
            return (
                new uint8[](0),
                new uint256[](0),
                new address[](0),
                new uint256[](0),
                new bytes32[](0)
            );
        }
        uint256 end = offset + limit;
        if (end > len) end = len;
        uint256 sliceLen = end - offset;

        entryTypes = new uint8[](sliceLen);
        refIds = new uint256[](sliceLen);
        actors = new address[](sliceLen);
        atBlocks = new uint256[](sliceLen);
        extraHashes = new bytes32[](sliceLen);

        for (uint256 i = 0; i < sliceLen; i++) {
            AuditLogEntry storage e = _auditLog[offset + i];
            entryTypes[i] = e.entryType;
            refIds[i] = e.refId;
            actors[i] = e.actor;
            atBlocks[i] = e.atBlock;
            extraHashes[i] = e.extraHash;
        }
    }

    function getTunnelConfigsBatch(uint256[] calldata tunnelIds) external view returns (
        address[] memory subscribers,
        bytes32[] memory configHashes,
        uint8[] memory regionIds,
        uint256[] memory expiresAtBlocks,
        uint256[] memory bandwidthCreditsWei,
        uint256[] memory createdAtBlocks,
        bool[] memory revoked
    ) {
        uint256 n = tunnelIds.length;
        subscribers = new address[](n);
        configHashes = new bytes32[](n);
        regionIds = new uint8[](n);
        expiresAtBlocks = new uint256[](n);
        bandwidthCreditsWei = new uint256[](n);
        createdAtBlocks = new uint256[](n);
        revoked = new bool[](n);
        for (uint256 i = 0; i < n; i++) {
            TunnelConfig storage tc = tunnelConfigs[tunnelIds[i]];
            subscribers[i] = tc.subscriber;
            configHashes[i] = tc.configHash;
