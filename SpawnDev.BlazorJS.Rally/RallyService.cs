using SpawnDev.BlazorJS.JSObjects.WebRTC;
using SpawnDev.BlazorJS.MessagePack;
using SpawnDev.BlazorJS.Rally.Signals;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SpawnDev.BlazorJS.Rally
{
    /// <summary>
    /// RallyService enables joining peer swarms using WebRTC and multiple distributed signalers to enable network adaptability and resiliency.<br/>
    /// </summary>
    public class RallyService : IAsyncBackgroundService
    {
        /// <summary>
        /// WebSocket signaler urls. Multiple signalers allows for better redundancy in establishing connections to peers.
        /// </summary>
        public List<string> SignalerUrls { get; } = new List<string>
        {

        };
        /// <summary>
        /// Whether to allow webrtc connection "trickle"<br/>
        /// The is an issue with Firefox when this is true
        /// </summary>
        public bool Trickle { get; set; } = false;
        /// <summary>
        /// The RTCConfiguration to use for WebRTC connections
        /// </summary>
        public RTCConfiguration? RTCConfiguration { get; set; }
        Task? _Ready;
        /// <inheritdoc/>
        public Task Ready => _Ready ??= InitAsync();
        /// <summary>
        /// Returns the current list of signalers
        /// </summary>
        public List<RallySignaler> Signalers => _Signalers.Values.ToList();
        Dictionary<string, RallySignaler> _Signalers = new Dictionary<string, RallySignaler>();
        BlazorJSRuntime JS;
        /// <summary>
        /// Randomly generated peer id for this RallyService instance.<br/>
        /// Using a unique peer id for each instance is important to avoid connection issues with WebRTC peers.<br/>
        /// A random peer id is used to prevent collisions with other instances.<br/>
        /// </summary>
        public string PeerId { get; private set; }
        DeviceIdentityService DeviceIdentityService;
        IServiceProvider ServiceProvider;
        /// <summary>
        /// Returns true if WebRTC is enabled in this environment
        /// </summary>
        public bool WebRTCEnabled { get; }
        /// <summary>
        /// Fires when a RallyPoint is added
        /// </summary>
        public event Action<RallyPoint> OnRallyPointAdded = default!;
        /// <summary>
        /// Fires when a RallyPoint is removed
        /// </summary>
        public event Action<RallyPoint> OnRallyPointRemoved = default!;
        /// <summary>
        /// 
        /// </summary>
        /// <param name="js"></param>
        /// <param name="serviceProvider"></param>
        /// <param name="deviceIdentityService"></param>
        public RallyService(BlazorJSRuntime js, DeviceIdentityService deviceIdentityService, IServiceProvider serviceProvider)
        {
            JS = js;
            ServiceProvider = serviceProvider;
            DeviceIdentityService = deviceIdentityService;
            WebRTCEnabled = JS.IsWindow;
            PeerId = GeneratePeerId();
            JS.Log("PeerId", PeerId); // Ex. "-WW0202-lfAgTpckKaD4"
            JS.Set("_connect", (string infoHash) =>
            {
                RallyPointConnect(infoHash);
            });
            JS.Set("_connectd", (string infoHash) =>
            {
                RallyPointConnect(infoHash, enabled: false);
            });
            JS.Set("_disable", (string infoHash) =>
            {
                var th = GetRallyPoint(infoHash);
                if (th != null) th.Enabled = false;
            });
            JS.Set("_enable", (string infoHash) =>
            {
                var th = GetRallyPoint(infoHash);
                if (th != null) th.Enabled = true;
            });
            JS.Set("_disconnect", (string infoHash) =>
            {
                var th = GetRallyPoint(infoHash);
                th?.Dispose();
            });
            JS.Set("_scrape", () =>
            {
                foreach (var t in Signalers)
                {
                    _ = t.Scrape();
                }
            });
        }
        /// <summary>
        /// Two characters for client id
        /// </summary>
        public const string ClientId = "WW";
        /// <summary>
        /// four ascii digits for version number
        /// </summary>
        public const string Version = "0202";
        /// <summary>
        /// Prepended to the peer id
        /// </summary>
        public static string VERSION_PREFIX { get; } = $"-{ClientId}{Version}-";
        static string UrlBase64Encode(byte[] toEncodeAsBytes)
        {
            return Convert.ToBase64String(toEncodeAsBytes).TrimEnd(padding).Replace('+', '-').Replace('/', '_');
        }
        static readonly char[] padding = { '=' };
        static string GeneratePeerId()
        {
            var andId = RandomNumberGenerator.GetBytes(9);
            var urlBase64EncodedBytes = UrlBase64Encode(andId);
            var ret = $"{VERSION_PREFIX}{urlBase64EncodedBytes}";
            return ret;
        }
        async Task InitAsync()
        {
            await Task.WhenAll(new Task[]
            {
                DeviceIdentityService.Ready,
                SimplePeer.SimplePeer.Init(),
                MessagePackSerializer.Init(),
            });
        }
        /// <summary>
        /// Connecting or connected peers across all signalers
        /// </summary>
        public List<RallyPeer> ConnectingOrConnectedPeers => Signalers.SelectMany(o => o.ConnectingOrConnectedPeers).ToList();
        /// <summary>
        /// Connecting peers across all signalers
        /// </summary>
        public List<RallyPeer> ConnectingPeers => Signalers.SelectMany(o => o.ConnectingPeers).ToList();
        /// <summary>
        /// Connected peers across all signalers
        /// </summary>
        public List<RallyPeer> ConnectedPeers => Signalers.SelectMany(o => o.ConnectedPeers).ToList();
        /// <summary>
        /// Ready peers across all signalers
        /// </summary>
        public List<RallyPeer> ReadyPeers => Signalers.SelectMany(o => o.ReadyPeers).ToList();
        /// <summary>
        /// Fires when a peer connects
        /// </summary>
        public event Action<RallyPeer>? OnPeerConnect = default!;
        /// <summary>
        /// Fires when a peer closes
        /// </summary>
        public event Action<RallyPeer>? OnPeerClose = default!;
        string InfoHashAny(string input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (input.Length == 40 && Regex.IsMatch(input, "[0-9a-fA-F]{40}")) return input;
            var sha1 = SHA1Hash(input);
            return sha1;
        }
        /// <summary>
        /// Generates a SHA1 hash of the input string and returns it as a hex string
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public string SHA1Hash(string input) => SHA1.HashData(Encoding.UTF8.GetBytes(input)).ToHexString();
        /// <summary>
        /// Generates a SHA1 hash of the input byte array and returns it as a hex string
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public string SHA1Hash(byte[] input) => SHA1.HashData(input).ToHexString();
        /// <summary>
        /// Connects to a rally point for the given info hash
        /// </summary>
        /// <param name="infoHash"></param>
        /// <param name="signalerUrls"></param>
        /// <param name="enabled"></param>
        /// <param name="numWant"></param>
        /// <returns></returns>
        public RallyPoint? RallyPointConnect(string infoHash, string[]? signalerUrls = null, bool enabled = true, int? numWant = null)
        {
            return RallyPointConnect(infoHash, out var rallyPoint, signalerUrls, enabled, numWant) ? rallyPoint : null;
        }
        /// <summary>
        /// Connects to a rally point for the given info hash
        /// </summary>
        /// <param name="infoHash"></param>
        /// <param name="rallyPoint"></param>
        /// <param name="signalerUrls"></param>
        /// <param name="enabled"></param>
        /// <param name="numWant"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public bool RallyPointConnect(string infoHash, out RallyPoint rallyPoint, string[]? signalerUrls = null, bool enabled = true, int? numWant = null)
        {
            var added = false;
            if (infoHash == null) throw new ArgumentNullException(nameof(infoHash));
            var infoHashSource = infoHash;
            infoHash = InfoHashAny(infoHash);
            if (!_RallyPoints.TryGetValue(infoHash, out rallyPoint!))
            {
                rallyPoint = new RallyPoint(this, infoHash, infoHashSource, enabled, numWant);
                if (numWant != null) rallyPoint.NumWant = numWant.Value;
                _RallyPoints[infoHash] = rallyPoint;
                rallyPoint.OnDisposed += (th) =>
                {
                    _RallyPoints.Remove(th.InfoHash);
                    OnRallyPointRemoved?.Invoke(th);
                };
                added = true;
                OnRallyPointAdded?.Invoke(rallyPoint);
            }
            signalerUrls ??= SignalerUrls.ToArray();
            foreach (var signalerUrl in signalerUrls)
            {
                var signaler = GetSignaler(signalerUrl, true)!;
                rallyPoint.AddSignaler(signaler);
            }
            return added;
        }
        /// <summary>
        /// Gets or creates a RallySignaler for the given signaler url
        /// </summary>
        /// <param name="signalerUrl"></param>
        /// <param name="allowCreate"></param>
        /// <returns></returns>
        public RallySignaler? GetSignaler(string signalerUrl, bool allowCreate = false)
        {
            if (!_Signalers.TryGetValue(signalerUrl, out var signaler) && allowCreate)
            {
                signaler = new RallySignaler(JS, this, DeviceIdentityService, ServiceProvider, PeerId, signalerUrl);
                signaler.OnBeforeUpdate = Signaler_OnBeforeUpdate;
                signaler.OnPeerFilter += Signaler_OnPeerFilter;
                signaler.OnPeerConnect += Signaler_OnPeerConnect;
                signaler.OnPeerClose += Signaler_OnPeerClose;
                _Signalers.Add(signalerUrl, signaler);
            }
            return signaler;
        }
        /// <summary>
        /// Gets the RallyPoint for the given info hash
        /// </summary>
        /// <param name="infoHash"></param>
        /// <returns></returns>
        public RallyPoint? GetRallyPoint(string infoHash)
        {
            if (infoHash == null) return null;
            infoHash = InfoHashAny(infoHash);
            return _RallyPoints.TryGetValue(infoHash, out var rallyPoint) ? rallyPoint : null;
        }
        Dictionary<string, RallyPoint> _RallyPoints = new Dictionary<string, RallyPoint>();
        /// <summary>
        /// Gets the list of active RallyPoints
        /// </summary>
        public List<RallyPoint> RallyPoints => _RallyPoints.Values.ToList();
        private void Signaler_OnPeerFilter(PeerFilterEventArgs args)
        {
            if (args.Ignore)
            {
                return;
            }
            if (!WebRTCEnabled)
            {
                args.Ignore = true;
                return;
            }
            //// Check if we already have this peer for this infohash
            //var existingPeer = ConnectingOrConnectedPeers.FirstOrDefault(o => o.RemotePeerId == args.RemotePeerId && o.InfoHash == args.InfoHash);
            //if (existingPeer != null)
            //{
            //    args.Ignore = true;
            //}
        }
        private void Signaler_OnPeerClose(RallyPeer peer)
        {
            if (_RallyPoints.TryGetValue(peer.InfoHash, out var rallyPoint))
            {
                OnPeerClose?.Invoke(peer);
            }
        }
        private void Signaler_OnPeerConnect(RallyPeer peer)
        {
            if (_RallyPoints.TryGetValue(peer.InfoHash, out var rallyPoint))
            {
                OnPeerConnect?.Invoke(peer);
            }
        }
        private void Signaler_OnRallyPointStatsUpdated(RallySignaler signaler, RallyPoint rallyPoint)
        {

        }
        Task Signaler_OnBeforeUpdate(RallySignaler signaler, RallyPoint rallyPoint)
        {
            return Task.CompletedTask;
        }
    }
}
