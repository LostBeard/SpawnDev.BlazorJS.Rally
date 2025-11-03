using SpawnDev.BlazorJS.Rally.Signals;

namespace SpawnDev.BlazorJS.Rally
{
    /// <summary>
    /// RallyPoints are virtual locations where swarms of peers connect using a shared info hash.<br/>
    /// </summary>
    public class RallyPoint : IDisposable
    {
        Dictionary<string, RallyPointStats> _SwarmStats { get; } = new Dictionary<string, RallyPointStats>();
        /// <summary>
        /// All swarm stats for this info hash
        /// </summary>
        public List<RallyPointStats> SwarmStats => _SwarmStats.Values.ToList();
        /// <summary>
        /// Get specific swarm stats for a signaler url
        /// </summary>
        /// <param name="signalerUrl"></param>
        /// <returns></returns>
        public RallyPointStats? GetSwarmStats(string signalerUrl) => GetSwarmStats(signalerUrl, false);
        internal RallyPointStats? GetSwarmStats(string signalerUrl, bool allowCreate)
        {
            if (_SwarmStats.TryGetValue(signalerUrl, out var stats) || !allowCreate) return stats;
            stats = new RallyPointStats
            {
                SignalerUrl = signalerUrl,
            };
            _SwarmStats[signalerUrl] = stats;
            return stats;
        }
        internal bool UpdateSwarmStats(string signalerUrl, int? complete, int? incomplete, int? interval)
        {
            var changed = complete != null || incomplete != null || interval != null;
            if (changed)
            {
                var stats = GetSwarmStats(signalerUrl, true)!;
                if (complete != null) stats.CompletePeers = complete.Value;
                if (incomplete != null) stats.IncompletePeers = incomplete.Value;
                if (interval != null) stats.Interval = interval.Value;
                stats.LastUpdated = DateTime.UtcNow;
                TriggerOnUpdated(stats);
            }
            return changed;
        }
        internal void ResetSignalerState(string signalerUrl)
        {
            var stats = GetSwarmStats(signalerUrl, true)!;
            if (!stats.InSwarm && !stats.CompletedSent && stats.State == "stopped")
            {
                return;
            }
            stats.InSwarm = false;
            stats.CompletedSent = false;
            stats.State = "stopped";
            stats.LastUpdated = DateTime.UtcNow;
            TriggerOnUpdated(stats);
        }
        internal void UpdateSignalerState(string signalerUrl, string state)
        {
            var stats = GetSwarmStats(signalerUrl, true)!;
            stats.State = state;
            if (state == "started")
            {
                stats.InSwarm = true;
            }
            if (state == "stopped")
            {
                stats.InSwarm = false;
            }
            if (state == "completed")
            {
                stats.CompletedSent = true;
            }
            stats.LastUpdated = DateTime.UtcNow;
            TriggerOnUpdated(stats);
        }
        void TriggerOnUpdated(RallyPointStats stats)
        {
            //Console.WriteLine($"RallyPoint {ConnectedSignalers.Count} {ConnectedPeers.Count} {InfoHash} {stats.SignalerUrl} {stats.InSwarm} {stats.CompletePeers} {stats.IncompletePeers} {stats.State} {stats.Interval}");
            OnUpdated?.Invoke(this, stats);
        }
        /// <summary>
        /// Fires when swarm stats are updated
        /// </summary>
        public event Action<RallyPoint, RallyPointStats> OnUpdated = default!;
        /// <summary>
        /// The client
        /// </summary>
        public List<RallySignaler> Signalers { get; } = new List<RallySignaler>();
        /// <summary>
        /// Connecting or connected peers for this info hash across all signalers
        /// </summary>
        public List<RallyPeer> ConnectingOrConnectedPeers => Signalers.SelectMany(o => o.ConnectingOrConnectedPeers.Where(o => o.InfoHash == InfoHash)).ToList();
        /// <summary>
        /// Connecting peers for this info hash across all signalers
        /// </summary>
        public List<RallyPeer> ConnectingPeers => Signalers.SelectMany(o => o.ConnectingPeers.Where(o => o.InfoHash == InfoHash)).ToList();
        /// <summary>
        /// Connected peers for this info hash across all signalers
        /// </summary>
        public List<RallyPeer> ConnectedPeers => Signalers.SelectMany(o => o.ConnectedPeers.Where(o => o.InfoHash == InfoHash)).ToList();
        /// <summary>
        /// Ready peers for this info hash across all signalers
        /// </summary>
        public List<RallyPeer> ReadyPeers => Signalers.SelectMany(o => o.ReadyPeers.Where(o => o.InfoHash == InfoHash)).ToList();
        /// <summary>
        /// Peers for this info hash across all signalers, in any state.
        /// </summary>
        public List<RallyPeer> Peers => Signalers.SelectMany(o => o.Peers.Where(o => o.InfoHash == InfoHash)).ToList();
        /// <summary>
        /// Connected signalers for this info hash
        /// </summary>
        public List<RallySignaler> ConnectedSignalers => Signalers.Where(o => o.Connected).ToList();
        /// <summary>
        /// THe info hash being tracked
        /// </summary>
        public string InfoHash { get; init; }
        /// <summary>
        /// If the infohash was added from a source other than the raw info hash (like a magnet link), this is the original source string.<br/>
        /// </summary>
        public string InfoHashSource { get; init; }
        /// <summary>
        /// The amount of data uploaded
        /// </summary>
        public long Uploaded { get; set; }
        /// <summary>
        /// The amount of data downloaded
        /// </summary>
        public long Downloaded { get; set; }
        /// <summary>
        /// The amount of data left to download of the total.<br/>
        /// null if unknown
        /// </summary>
        public long? Left { get; set; }
        /// <summary>
        /// The number of peers to try to connect to on the next update
        /// </summary>
        public int NumWant { get; set; } = 5;
        /// <summary>
        /// The maximum number of peers to connect to on this RallyPoint
        /// </summary>
        public int MaxPeerCount { get; set; } = 32;
        /// <summary>
        /// The number of peers to try to connect to on the next update
        /// </summary>
        public int NumWantNow => Math.Min(NumWant, Math.Max(MaxPeerCount - ConnectingOrConnectedPeers.Count, 0));
        /// <summary>
        /// The ECDSA public keys, in spki lowercase hex string format,<br/>
        /// of the peers we want to connect to on this RallyPoint.<br/>
        /// When this list has values, only these peers will be allowed to connect via this RallyPoint.<br/>
        /// When this list has values, the values (or a subset of) will be used as the audience for generated offers.
        /// </summary>
        public List<string> PeersWanted { get; } = new List<string>();
        /// <summary>
        /// When not enabled, no more connections will be accepted for this info hash, but signalers will stay connected.<br/>
        /// The signaler will disconnect from this info hash swarm when set to false.
        /// </summary>
        public bool Enabled
        {
            get => _Enabled;
            set
            {
                if (_Enabled == value) return;
                _Enabled = value;
                Update();
            }
        }
        bool _Enabled = true;
        /// <summary>
        /// If set to true, no peers will be requested through the signaler if at least 1 peer is already connected on via signaler.<br/>
        /// This helps take the load of the server while still allowing new peer connections through existing peers.
        /// </summary>
        public bool BootStrapOnly { get; set; } = false;
        /// <summary>
        /// Sends update to all signalers
        /// </summary>
        public void Update()
        {
            foreach (var t in Signalers)
            {
                _ = t.Update(this);
            }
        }
        /// <summary>
        /// Returns true if there are 0 bytes left to download
        /// </summary>
        public bool Complete => Left == 0;
        RallyService RallyService;
        /// <summary>
        /// 
        /// </summary>
        /// <param name="rallyService"></param>
        /// <param name="infoHash"></param>
        /// <param name="infoHashSource"></param>
        /// <param name="enabled"></param>
        /// <param name="numWant"></param>
        internal RallyPoint(RallyService rallyService, string infoHash, string infoHashSource, bool enabled, int? numWant)
        {
            InfoHash = infoHash;
            InfoHashSource = infoHashSource;
            RallyService = rallyService;
            Enabled = enabled;
            if (numWant != null) NumWant = numWant.Value;
        }
        /// <summary>
        /// Fires when the rally point is disposed
        /// </summary>
        public event Action<RallyPoint> OnDisposed = default!;
        /// <summary>
        /// Returns true if disposed
        /// </summary>
        public bool IsDisposed { get; private set; } = false;
        /// <summary>
        /// Disposes the rally point and disconnects from all signalers
        /// </summary>
        public void Dispose()
        {
            if (IsDisposed) return;
            IsDisposed = true;
            foreach (var peer in ConnectedPeers)
            {
                peer.Connection.Destroy();
            }
            foreach (var signaler in Signalers.ToArray())
            {
                RemoveSignaler(signaler);
            }
            OnDisposed?.Invoke(this);
        }
        /// <summary>
        /// Adds a signaler to this rally point
        /// </summary>
        /// <param name="signalerUrl"></param>
        public void AddSignaler(string signalerUrl)
        {
            var signaler = RallyService.GetSignaler(signalerUrl, true)!;
            AddSignaler(signaler);
        }
        /// <summary>
        /// Adds a signaler to this rally point
        /// </summary>
        /// <param name="signaler"></param>
        public void AddSignaler(RallySignaler signaler)
        {
            if (signaler == null || Signalers.Contains(signaler)) return;
            Signalers.Add(signaler);
            signaler.AddRallyPoint(this);
            signaler.OnPeerFilter += Signaler_OnPeerFilter;
            signaler.OnPeerConnect += Signaler_OnPeerConnect;
            signaler.OnPeerClose += Signaler_OnPeerClose;
        }
        /// <summary>
        /// Removes a signaler from this rally point
        /// </summary>
        /// <param name="signalerUrl"></param>
        public void RemoveSignaler(string signalerUrl)
        {
            var signaler = Signalers.FirstOrDefault(o => o.Url == signalerUrl);
            if (signaler == null) return;
            RemoveSignaler(signaler);
        }
        /// <summary>
        /// Removes a signaler from this rally point
        /// </summary>
        /// <param name="signaler"></param>
        public void RemoveSignaler(RallySignaler signaler)
        {
            if (!Signalers.Contains(signaler)) return;
            Signalers.Remove(signaler);
            signaler.RemoveHash(InfoHash);
            signaler.OnPeerFilter -= Signaler_OnPeerFilter;
            signaler.OnPeerConnect -= Signaler_OnPeerConnect;
            signaler.OnPeerClose -= Signaler_OnPeerClose;
        }
        private void Signaler_OnPeerFilter(PeerFilterEventArgs args)
        {
            if (args.Ignore)
            {
                return;
            }
            if (args.InfoHash == InfoHash)
            {
                //// Check if we already have this peer for this infohash
                //var existingPeer = ConnectedPeers.FirstOrDefault(o => o.RemotePeerId == args.RemotePeerId && o.InfoHash == args.InfoHash);
                //if (existingPeer != null)
                //{
                //    args.Ignore = true;
                //}
            }
        }
        private void Signaler_OnPeerClose(RallyPeer peer)
        {
            if (peer.InfoHash != InfoHash) return;
            OnPeerClose?.Invoke(this, peer);
        }
        private void Signaler_OnPeerConnect(RallyPeer peer)
        {
            if (peer.InfoHash != InfoHash) return;
            OnPeerConnect?.Invoke(this, peer);
            //var otherConnectedToThisPeer = ConnectingOrConnectedPeers.Where(o => o.RemoteSignerKeyHex == peer.RemoteSignerKeyHex && o != peer && o.Connected).ToList();
            //var otherConnectingToThisPeer = ConnectingOrConnectedPeers.Where(o => o.RemoteSignerKeyHex == peer.RemoteSignerKeyHex && o != peer && o.Connecting).ToList();
            //if (otherConnectedToThisPeer.Any())
            //{
            //    // there are already other connections to this peer
            //    peer.Dispose();
            //}
            //// dispose any connections in progress
            //foreach (var connectingPeer in otherConnectingToThisPeer)
            //{
            //    connectingPeer.Dispose();
            //}
        }
        /// <summary>
        /// Fires when a peer connects to this rally point
        /// </summary>
        public event Action<RallyPoint, RallyPeer>? OnPeerConnect = default!;
        /// <summary>
        /// Fires when a peer closes connection to this rally point
        /// </summary>
        public event Action<RallyPoint, RallyPeer>? OnPeerClose = default!;
    }
}
