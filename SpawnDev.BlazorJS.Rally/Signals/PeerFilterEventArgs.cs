namespace SpawnDev.BlazorJS.Rally.Signals
{
    /// <summary>
    /// Event args created when a peer connection is about to be established.<br/>
    /// Set the Ignore property to true to prevent the connection from being created.
    /// </summary>
    public class PeerFilterEventArgs
    {
        /// <summary>
        /// This is the ECDH public key of the remote peer in hex format.<br/>
        /// This is the id that should be used to identify peers.<br/>
        /// More specifically to identify peer devices.<br/>
        /// This key is verified before the RallyPeer is enabled.
        /// </summary>
        public string RemoteSignerKeyHex { get; set; } = default!;
        /// <summary>
        /// The remote peer id used for communication with signalers.
        /// </summary>
        public string RemotePeerId { get; set; } = default!;
        /// <summary>
        /// If set to true, no connection to the peer will be created.
        /// </summary>
        public bool Ignore { get; set; } = false;
        /// <summary>
        /// The rally point info hash.
        /// </summary>
        public string InfoHash { get; set; } = default!;
    }
}
