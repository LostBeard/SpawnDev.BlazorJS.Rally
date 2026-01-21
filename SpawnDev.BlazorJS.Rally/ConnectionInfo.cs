namespace SpawnDev.BlazorJS.Rally
{
    /// <summary>
    /// Connection info shared between peers
    /// </summary>
    public class ConnectionInfo
    {
        /// <summary>
        /// Explicit conversion to ConnectionInfo
        /// </summary>
        /// <param name="rallyPeer"></param>
        public static implicit operator ConnectionInfo(RallyPeer? rallyPeer) => rallyPeer == null ? null! : new ConnectionInfo(rallyPeer);
        /// <summary>
        /// Explicit conversion to ConnectionInfo
        /// </summary>
        /// <param name="rallySignaler"></param>
        public static implicit operator ConnectionInfo(RallySignaler? rallySignaler) => rallySignaler == null ? null! : new ConnectionInfo(rallySignaler);
        /// <summary>
        /// New instance
        /// </summary>
        /// <param name="rallyPeer"></param>
        public ConnectionInfo(RallyPeer rallyPeer)
        {
            PeerId = rallyPeer.RemotePeerId;
            SignerKeyHex = rallyPeer.RemoteSignerKeyHex;
            SignalerUrl = rallyPeer.SignalerUrl;
            Type = "peer";
            Connected = rallyPeer.Connected;
            Connecting = rallyPeer.Connecting;
            ConnectionId = rallyPeer.OfferId;
            Initiator = rallyPeer.Initiator;
        }
        /// <summary>
        /// New instance
        /// </summary>
        /// <param name="rallySignaler"></param>
        public ConnectionInfo(RallySignaler rallySignaler)
        {
            PeerId = rallySignaler.Url;
            SignalerUrl = rallySignaler.Url;
            Type = "signaler";
            Connected = rallySignaler.Connected;
            ConnectionId = rallySignaler.Url;
            Initiator = true;
        }
        /// <summary>
        /// New instance
        /// </summary>
        public ConnectionInfo() { }
        /// <summary>
        /// Peer id (if a peer)<br/>
        /// Signaler url if a signaler
        /// </summary>
        public string PeerId { get; init; }
        /// <summary>
        /// Connection id
        /// </summary>
        public string ConnectionId { get; init; }
        /// <summary>
        /// Peer signer key (if a peer)
        /// </summary>
        public string? SignerKeyHex { get; init; }
        /// <summary>
        /// Signaler url
        /// </summary>
        public string? SignalerUrl { get; init; }
        /// <summary>
        /// Connection type
        /// </summary>
        public string Type { get; init; }
        /// <summary>
        /// True if connected
        /// </summary>
        public bool Connected { get; init; }
        public bool Initiator { get; init; }
        public bool Connecting { get; init; }
    }
}
