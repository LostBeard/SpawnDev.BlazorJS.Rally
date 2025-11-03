using SpawnDev.BlazorJS.JSObjects;
using SpawnDev.BlazorJS.JSObjects.WebRTC;
using SpawnDev.BlazorJS.Rally.Signals;
using SpawnDev.BlazorJS.SimplePeer;
using SpawnDev.BlazorJS.WebWorkers;
using System;
using System.Text.Json;
using Timer = System.Timers.Timer;

namespace SpawnDev.BlazorJS.Rally
{
    /// <summary>
    /// Handles relaying messages between peers via a web socket server based on a key, referred to as the info hash
    /// </summary>
    public class RallySignaler
    {
        WebSocket? webSocket;
        IServiceProvider ServiceProvider;
        Timer? timer;
        static double DefaultIntervalSeconds = 30;
        Timer? idleDisconnectTimer;
        DeviceIdentityService DeviceIdentityService;
        RallyService RallyService;
        /// <summary>
        /// Creates a new instance
        /// </summary>
        /// <param name="js"></param>
        /// <param name="rallyService"></param>
        /// <param name="deviceIdentityService"></param>
        /// <param name="serviceProvider"></param>
        /// <param name="peerId"></param>
        /// <param name="url"></param>
        public RallySignaler(BlazorJSRuntime js, RallyService rallyService, DeviceIdentityService deviceIdentityService, IServiceProvider serviceProvider, string peerId, string url)
        {
            JS = js;
            RallyService = rallyService;
            DeviceIdentityService = deviceIdentityService;
            ServiceProvider = serviceProvider;
            Url = url;
            PeerId = peerId;
            timer = new Timer(DefaultIntervalSeconds * 1000);
            timer.Elapsed += Timer_Elapsed;
            timer.Enabled = true;
            _ = Connect();
        }
        void StopIdleDisconnectTimer()
        {
            if (idleDisconnectTimer != null)
            {
                idleDisconnectTimer.Stop();
                idleDisconnectTimer.Dispose();
                idleDisconnectTimer = null;
            }
        }
        /// <summary>
        /// How long to wait after the last RallyPoint has been removed before disconnecting
        /// </summary>
        public int IdleDisconnectSeconds { get; set; } = 15;
        void StartIdleDisconnectTimer()
        {
            StopIdleDisconnectTimer();
            idleDisconnectTimer = new Timer(IdleDisconnectSeconds * 1000);
            idleDisconnectTimer.Elapsed += IdleDisconnectTimer_Elapsed;
            idleDisconnectTimer.AutoReset = false;
            idleDisconnectTimer.Start();
        }
        private void IdleDisconnectTimer_Elapsed(object? sender, System.Timers.ElapsedEventArgs e)
        {
            StopIdleDisconnectTimer();
            if (!RallyPoints.Any())
            {
                webSocket?.Close();
            }
        }
        private void Timer_Elapsed(object? sender, System.Timers.ElapsedEventArgs e)
        {
            _ = Update();
        }
        /// <summary>
        /// Fires before updating the server
        /// </summary>
        public event Action<RallySignaler> OnUpdating = default!;
        /// <summary>
        /// Returns true when running an update
        /// </summary>
        public bool Updating { get; set; } = false;
        /// <summary>
        /// Updates all RallyPoints.<br/>
        /// This will be called automatically based on the server set update interval.
        /// </summary>
        /// <returns></returns>
        public async Task Update()
        {
            var readyState = webSocket?.ReadyState ?? -1;
            if (readyState != 1) return;
            if (Updating) return;
            Updating = true;
            OnUpdating?.Invoke(this);
            foreach (var th in _RallyPoints.Values)
            {
                await Update(th);
            }

            Updating = false;
        }
        /// <summary>
        /// The amount of seconds between update announce messages
        /// </summary>
        public int UpdateIntervalSeconds
        {
            get => (int)(timer?.Interval / 1000 ?? 0);
            set
            {
                if (timer != null)
                {
                    timer.Interval = value * 1000;
                }
            }
        }
        TaskCompletionSource connectTaskSource = new TaskCompletionSource();
        /// <summary>
        /// Completes when the web socket connection to the server connects
        /// </summary>
        /// <returns></returns>
        public async Task AwaitConnected()
        {
            if (Disposed) return;
            if (webSocket?.ReadyState == 1) return;
            if (connectTaskSource == null || connectTaskSource.Task.IsCompleted)
            {
                connectTaskSource = new TaskCompletionSource();
            }
            await connectTaskSource.Task;
        }
        async Task Connect()
        {
            while (!Disposed)
            {
                var readyState = webSocket?.ReadyState ?? -1;
                if ((webSocket == null || webSocket.ReadyState > 1) && RallyPoints.Any())
                {
                    DisposeSocket();
                    webSocket = new WebSocket(Url);
                    webSocket.OnMessage += WebSocket_OnMessage;
                    webSocket.OnError += WebSocket_OnError;
                    webSocket.OnOpen += WebSocket_OnOpen;
                    webSocket.OnClose += WebSocket_OnClose;
                }
                if (Disposed) break;
                await Task.Delay(5000);
            }
        }
        void DisposeSocket()
        {
            if (webSocket != null)
            {
                if (webSocket.ReadyState <= 1)
                {
                    try
                    {
                        webSocket.Close();
                    }
                    catch { }
                }
                webSocket.OnMessage -= WebSocket_OnMessage;
                webSocket.OnError -= WebSocket_OnError;
                webSocket.OnOpen -= WebSocket_OnOpen;
                webSocket.OnClose -= WebSocket_OnClose;
                webSocket.Dispose();
                webSocket = null;
            }
        }
        /// <summary>
        /// This method can be called by remotely to relay a signed offer from another peer
        /// </summary>
        /// <param name="signalerUrl"></param>
        /// <param name="infoHash"></param>
        /// <param name="offerId"></param>
        /// <param name="sdpMessage"></param>
        /// <param name="rallyService"></param>
        /// <param name="rallyPeer"></param>
        /// <returns></returns>
        [RemoteCallable]
        static async Task HandleRelayedPeerOffer(string signalerUrl, string infoHash, string offerId, RTCSessionDescription sdpMessage, [FromServices] RallyService rallyService, [FromLocal] RallyPeer rallyPeer)
        {
            //Console.WriteLine($"Got offer from {remotePeerId} relayed by {rallyPeer.RemotePeerId}");
            try
            {
                if (rallyPeer == null)
                {
                    throw new Exception($"{nameof(rallyPeer)} is null");
                }
                if (rallyService == null)
                {
                    throw new Exception($"{nameof(rallyService)} is null");
                }
                if (rallyPeer.RemotePeerId == rallyService.PeerId)
                {
                    return;
                }
                if (sdpMessage == null) return;
                var rallyPoint = rallyService.GetRallyPoint(infoHash);
                if (rallyPoint == null) return;
                var rallySignaler = rallyService.GetSignaler(signalerUrl);
                if (rallySignaler == null) return;
                await rallySignaler.HandlePeerMessage(rallyPoint, offerId, sdpMessage, true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"HandleRelayedPeerOffer call failed: {ex.ToString()}");
            }
        }
        /// <summary>
        /// Handles offers and answers from peers
        /// </summary>
        /// <param name="rallyPoint"></param>
        /// <param name="offerId"></param>
        /// <param name="sdpMessage"></param>
        /// <param name="fromPeer"></param>
        /// <returns></returns>
        internal async Task HandlePeerMessage(RallyPoint rallyPoint, string offerId, RTCSessionDescription? sdpMessage, bool fromPeer)
        {
            if (fromPeer && !EnableRelayedUntargetedOffers && !EnableRelayedTargetedOffers) return;
            if (sdpMessage == null || rallyPoint == null || string.IsNullOrEmpty(offerId)) return;
            RallyPeer? peer = null;
            var signalJson = await SignalFromSdp(sdpMessage.Sdp);
            if (signalJson != null)
            {
                var signer = signalJson.Value.signer;
                var signerRemotePeerId = signalJson.Value.signerRemotePeerId;
                var audiences = signalJson.Value.audiences;
                var targeted = audiences != null && audiences.Length > 0;
                var targetsThis = audiences != null && (audiences.Contains(DeviceIdentityService.PublicSigningKeyHex) || audiences.Contains(PeerId));
                var targetsThisOnly = audiences?.Length == 1 && (audiences?.Contains(PeerId) ?? false);
                var fromThisPeer = signerRemotePeerId == PeerId;
                var rtcDesc = JSON.Parse(signalJson.Value.signal);
                var sdpType = rtcDesc!.JSRef!.Get<string>("type");
                var canCreate = sdpType == "offer";
                JS.Log(signerRemotePeerId, "targetsThis >> ", fromPeer, targetsThis, audiences, sdpType);
                // the message must be for us specifically or no one specific
                if (!fromThisPeer && (!targeted || targetsThis))
                {
                    // A peer is trying to respond to an offer we gave to the server in our announce message Offers
                    peer = GetPeerByOfferId(rallyPoint, offerId, signerRemotePeerId, signer, canCreate);
                    if (peer != null)
                    {
                        peer.Signal(signalJson.Value.signal);
                        if (fromPeer)
                        {
                            JS.Log("Successful direct connect!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", sdpType, signerRemotePeerId);
                        }
                    }
                }
                if (peer == null && !targetsThisOnly)
                {
                    await RelayMessage(rallyPoint, offerId, signerRemotePeerId, audiences, sdpMessage, fromPeer);
                }
            }
        }
        async Task<bool> RelayMessage(RallyPoint rallyPoint, string offerId, string fromPeerId, string[]? audiences, RTCSessionDescription sdpMessage, bool relayed)
        {
            var ret = false;
            var targeted = audiences != null && audiences.Any();
            // we didn't use the offer, check if we can pass it on to a target that we are connected to (if any), or a  random peer that might want to connect
            if (EnableRelayedTargetedOffers && audiences != null && audiences.Any())
            {
                // check if we are connected to any of the targets on this signaler url and the given rallyPoint
                var targetPeers = rallyPoint.ConnectedPeers.Where(o => o.SignalerUrl == Url && (audiences.Contains(o.RemoteSignerKeyHex) || audiences.Contains(o.RemotePeerId))).OrderBy(_ => rng.Next()).ToList();
                if (targetPeers.Any())
                {
                    // we are connected to a requested target. pass the offer to ONE them. they can ignore it if they want.
                    var designatedTarget = targetPeers.First();
                    JS.Log($"Relaying targeted offer from {fromPeerId} to {designatedTarget.RemotePeerId}");
                    try
                    {
                        await designatedTarget.Run(() => HandleRelayedPeerOffer(Url, rallyPoint.InfoHash, offerId, sdpMessage, null!, null!));
                    }
                    catch (Exception ex)
                    {
                        JS.Log("Targeted Offer relay failed:", ex.ToString());
                    }
                }
                else
                {
                    JS.Log("No target found for relay unused message from", fromPeerId, audiences, targetPeers.Any());
                }
            }
            else if (EnableRelayedUntargetedOffers && !targeted && !relayed)
            {
                // not targeted, relay to a random peer on this rally point and signaler
                var rallyPointPeers = rallyPoint.ConnectedPeers.Where(o => o.RemotePeerId != fromPeerId && o.SignalerUrl == Url).OrderBy(_ => rng.Next()).ToList();
                if (rallyPointPeers.Any())
                {
                    var designatedTarget = rallyPointPeers.First();
                    //JS.Log($"Relaying untargeted offer from {remotePeerId} to {designatedTarget.RemotePeerId}");
                    try
                    {
                        await designatedTarget.Run(() => HandleRelayedPeerOffer(Url, rallyPoint.InfoHash, offerId, sdpMessage, null!, null!));
                    }
                    catch (Exception ex)
                    {
                        JS.Log("Untargeted Offer relay failed:", ex.ToString());
                    }
                }
            }
            return ret;
        }
        bool EnableRelayedTargetedOffers = true;
        bool EnableRelayedUntargetedOffers = false;
        /// <summary>
        /// The delay in seconds to wait between updates sent to the server.<br/>
        /// This value will be received from the server.
        /// </summary>
        public int ScrapeInterval { get; private set; } = 30;
        async Task HandleSignalerMessage(string text)
        {
            try
            {
                var jsonData = JSON.Parse<SignalerMessageResponseMessage>(text);
                var action = jsonData.Action;
                switch (action)
                {
                    case "scrape":
                        JS.Log("scrapeResponse", text);
                        var scrapeInterval = jsonData.Flags?.MinRequestInterval;
                        if (scrapeInterval != null && ScrapeInterval != scrapeInterval.Value)
                        {
                            JS.Log("Scrape interval updated", Url);
                            ScrapeInterval = scrapeInterval.Value;
                        }
                        if (jsonData.Files != null)
                        {
                            jsonData.Files = jsonData.Files.ToDictionary(o => o.Key.CharStringToHexString(), o => o.Value);
                        }
                        scrapeTcs?.TrySetResult(jsonData.Files);
                        break;
                    case "announce":
                        var offerId = jsonData.OfferId;
                        var remotePeerId = jsonData.PeerId;
                        var rallyPoint = jsonData.InfoHash == null ? null : GetRallyPoint(jsonData.InfoHash);
                        if (rallyPoint != null)
                        {
                            rallyPoint.UpdateSwarmStats(Url, jsonData.Complete, jsonData.Incomplete, jsonData.Interval);
                            if (!string.IsNullOrEmpty(remotePeerId) && !string.IsNullOrEmpty(offerId))
                            {
                                await HandlePeerMessage(rallyPoint, offerId, jsonData.Answer, false);
                                await HandlePeerMessage(rallyPoint, offerId, jsonData.Offer, false);
                            }
                        }
                        if (jsonData.Interval != null)
                        {
                            var interval = jsonData.Interval.Value;
                            if (interval > 0)
                            {
                                var intervalClamped = Math.Clamp(interval, 15, 120);
                                if (UpdateIntervalSeconds != intervalClamped)
                                {
                                    JS.Log($"Changing interval: {intervalClamped} ({interval}) {Url}");
                                    UpdateIntervalSeconds = intervalClamped;
                                }
                            }
                        }
                        break;
                    default:
                        JS.Log("unknown action message", text);
                        break;
                }

            }
            catch (Exception ex)
            {
                JS.Log($"Error: {ex.ToString()}");
            }
        }
        async void WebSocket_OnMessage(MessageEvent e)
        {
            try
            {
                if (e.TypeOfData == "String")
                {
                    var text = e.GetData<string>();
                    await HandleSignalerMessage(text);
                }
            }
            catch (Exception ex)
            {
                JS.Log($"Error: {ex.ToString()}");
            }
        }
        private static Random rng = new Random();
        /// <summary>
        /// Sdp to signal
        /// </summary>
        /// <param name="sdp"></param>
        /// <returns></returns>
        async Task<(string signer, string signal, string[]? audiences, string signerRemotePeerId)?> SignalFromSdp(string sdp)
        {
            if (string.IsNullOrEmpty(sdp)) return null;
            try
            {
                var obj = JsonSerializer.Deserialize<SignedObject<string>>(sdp);
                if (obj == null) return null;
                if (obj.Signatures?.Count != 1) return null;
                var verified = await DeviceIdentityService.Verify(obj);
                var senderSignature = obj.Signatures.First();
                if (verified)
                {
                    // make sure the signature isn't too old
                    var diff = Math.Abs((DateTime.Now - senderSignature.TokenSigned).TotalMinutes);
                    if (diff < 10)
                    {
                        var signal = obj.Value;
                        var signer = senderSignature.PublicKey;
                        var audiences = obj.GetClaims("audience")?.ToArray();
                        var remotePeerIdClaimValue = obj.GetClaimFirstOrDefault("peerId");
                        //if (remotePeerIdClaimValue != remotePeerId)
                        //{
                        //    // the signer "peerId" claim value does not match what is being reported as the remote peer id. something is wrong, ignore.
                        //    return null;
                        //}
                        return (signer, signal, audiences, remotePeerIdClaimValue!);
                    }
                }
            }
            catch { }
            return null;
        }
        /// <summary>
        /// Signal to sdp.<br/>
        /// This method adds an audience indicator and signs the sdp message.<br/>
        /// </summary>
        /// <param name="signal"></param>
        /// <param name="audiences"></param>
        /// <returns></returns>
        async Task<string> SignalToSdp(string signal, params string[] audiences)
        {
            var obj = new SignedObject<string>
            {
                Value = signal
            };
            obj.AddClaim("peerId", PeerId);
            if (audiences.Length > 0)
            {
                foreach (var audience in audiences)
                {
                    obj.AddClaim("audience", audience ?? "");
                }
            }
            await DeviceIdentityService.Sign(obj);
            var ret = JsonSerializer.Serialize(obj);
            return ret;
        }
        /// <summary>
        /// Returns the tracked hash if it is being tracked
        /// </summary>
        /// <param name="infoHash"></param>
        /// <returns></returns>
        public RallyPoint? GetRallyPoint(string infoHash)
        {
            if (infoHash == null)
            {
                return null;
            }
            return _RallyPoints.TryGetValue(infoHash, out var th) ? th : null;
        }
        SemaphoreSlim _scrapeLimiter = new SemaphoreSlim(1, 1);
        TaskCompletionSource<Dictionary<string, FileStats>?>? scrapeTcs;
        /// <summary>
        /// Send a scrape query.<br/>
        /// Server support is optional
        /// </summary>
        /// <param name="infoHashes"></param>
        /// <returns></returns>
        public async Task<Dictionary<string, FileStats>?> Scrape(string[]? infoHashes = null)
        {
            Dictionary<string, FileStats>? ret = null;
            if (webSocket?.ReadyState != 1) return null;
            await _scrapeLimiter.WaitAsync();
            try
            {
                scrapeTcs = new TaskCompletionSource<Dictionary<string, FileStats>?>();
                var succ = SendMessage(new ScrapeQuery
                {
                    InfoHash = infoHashes
                });
                if (succ)
                {
                    ret = await scrapeTcs.Task.WaitAsync(TimeSpan.FromSeconds(10));
                    JS.Log("ret", ret);
                }
            }
            catch (Exception ex)
            {
                JS.Log("Scrape error", ex.ToString());
            }
            finally
            {
                scrapeTcs = null;
                _scrapeLimiter.Release();
            }
            return ret;
        }
        void WebSocket_OnError(Event e)
        {
            var source = connectTaskSource;
            connectTaskSource = new TaskCompletionSource();
            source?.TrySetException(new Exception("Failed"));
            if (Connected)
            {
                Connected = false;
                foreach (var th in _RallyPoints.Values)
                {
                    th.ResetSignalerState(Url);
                }
                scrapeTcs?.SetException(new Exception("Connection lost"));
                JS.Log("WebSocket_OnError (closed)", Url);
                OnDisconnected?.Invoke(this);
            }
        }
        /// <summary>
        /// Fires when disconnected from the signaler
        /// </summary>
        public event Action<RallySignaler> OnDisconnected = default!;
        /// <summary>
        /// Fires when connected to the signaler
        /// </summary>
        public event Action<RallySignaler> OnConnected = default!;
        /// <summary>
        /// Returns true if connected to the signaler
        /// </summary>
        public bool Connected { get; private set; }
        void WebSocket_OnOpen(Event e)
        {
            if (!Connected)
            {
                Connected = true;
                JS.Log("WebSocket_OnOpen", Url);
                OnConnected?.Invoke(this);
            }
            var source = connectTaskSource;
            connectTaskSource = new TaskCompletionSource();
            source?.SetResult();
            _ = Update();
        }
        void WebSocket_OnClose(CloseEvent e)
        {
            if (Connected)
            {
                Connected = false;
                foreach (var th in _RallyPoints.Values)
                {
                    th.ResetSignalerState(Url);
                }
                JS.Log("WebSocket_OnClose", Url);
                scrapeTcs?.SetException(new Exception("Connection lost"));
                OnDisconnected?.Invoke(this);
            }
        }
        bool SendMessage(object data)
        {
            try
            {
                if (webSocket?.ReadyState == 1)
                {
                    var json = JsonSerializer.Serialize(data, JsonSerializerOptionsWeb);
                    webSocket.Send(json);
                    return true;
                }
            }
            catch (Exception ex)
            {
                JS.Log($"Send failed: {ex.ToString()}");
            }
            return false;
        }
        static JsonSerializerOptions JsonSerializerOptionsWeb { get; } = new JsonSerializerOptions(JsonSerializerDefaults.Web) { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        Dictionary<string, RallyPoint> _RallyPoints { get; } = new Dictionary<string, RallyPoint>();
        /// <summary>
        /// List of RallyPoints
        /// </summary>
        public List<RallyPoint> RallyPoints => _RallyPoints.Values.ToList();
        /// <summary>
        /// The signaler url
        /// </summary>
        public string Url { get; set; }
        /// <summary>
        /// The peer id that identifies this instance on the signaler server
        /// </summary>
        public string PeerId { get; set; }
        BlazorJSRuntime JS;
        /// <summary>
        /// Called before a RallyPoint is updated with the signaler
        /// </summary>
        public Func<RallySignaler, RallyPoint, Task> OnBeforeUpdate = default!;
        /// <summary>
        /// started event
        /// </summary>
        public static readonly string STARTED = "started";
        /// <summary>
        /// stopped event
        /// </summary>
        public static readonly string STOPPED = "stopped";
        /// <summary>
        /// completed event
        /// </summary>
        public static readonly string COMPLETED = "completed";
        /// <summary>
        /// update event
        /// </summary>
        public static readonly string UPDATE = "update";
        /// <summary>
        /// paused event
        /// </summary>
        public static readonly string PAUSED = "paused";
        SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);
        /// <summary>
        /// Updates the signaler with a fresh set of offers and ask for updated swarm information
        /// </summary>
        /// <param name="rallyPoint"></param>
        /// <returns></returns>
        public async Task Update(RallyPoint rallyPoint)
        {
            try
            {
                await _semaphore.WaitAsync();
                var readyState = webSocket?.ReadyState ?? -1;
                if (readyState != 1) return;
                var infoHash = rallyPoint.InfoHash;
                //var lastEvent = GetLastRallyPointEvent(infoHash);
                var stats = rallyPoint.GetSwarmStats(Url, true)!;
                if (OnBeforeUpdate != null)
                {
                    await OnBeforeUpdate(this, rallyPoint);
                }
                if (rallyPoint.Enabled != stats.InSwarm)
                {
                    if (rallyPoint.Enabled)
                    {
                        // join the swarm
                        await SendStartedEvent(rallyPoint);
                    }
                    else
                    {
                        // leave the swarm
                        SendStoppedEvent(rallyPoint);
                    }
                }
                else if (stats.InSwarm)
                {
                    if (rallyPoint.Left == 0 && !stats.CompletedSent)
                    {
                        // the info hash is now complete and we have not told th server, do it now
                        SendCompletedEvent(rallyPoint);
                    }
                    else
                    {
                        // send default which us an update
                        await SendUpdateEvent(rallyPoint);
                    }
                    if (ConnectToPeersOnUpdate)
                    {
                        var connectedPeers = rallyPoint.ConnectedPeers.Where(o => o.SignalerUrl == Url).ToList();
                        foreach (var peer in connectedPeers)
                        {
                            await ConnectToPeers(peer);
                        }
                    }
                }
            }
            catch { }
            finally
            {
                _semaphore?.Release();
            }
        }
        async Task ConnectToPeers(RallyPeer peer)
        {
            var rallyPoint = peer.RallyPoint;
            // check if they know about any peers we might want to connect to
            foreach (var info in peer.ConnectionInfos)
            {
                // check for existing peer on this rally point with this peer (does not have to be on this signaler!)
                if (info.PeerId == PeerId)
                {
                    // this instance, we do not want to connect to ourselves
                    continue;
                }
                var existingPeer = rallyPoint.ConnectingOrConnectedPeers.FirstOrDefault(o => o.RemotePeerId == info.PeerId);
                if (existingPeer == null)
                {
                    // we can connect to this peer if desired
                    if (rallyPoint.NumWantNow > 0)
                    {
                        try
                        {
                            JS.Log($"Sending direct offer to peer: {info.PeerId}");
                            await ConnectToPeer(peer, rallyPoint, info.PeerId, info.SignerKeyHex);
                        }
                        catch (Exception ex)
                        {
                            JS.Log("Sending direct offer to peer failed", ex.ToString());
                        }
                    }
                }
            }
        }
        public bool ConnectToPeersOnUpdate { get; set; } = true;
        public bool ConnectToPeersOnConnect { get; set; } = true;
        async Task SendUpdateEvent(RallyPoint rallyPoint)
        {
            var numWant = rallyPoint.NumWantNow;
            var query = new AnnounceQueryUpdate
            {
                PeerId = PeerId,
                InfoHash = rallyPoint.InfoHash,
                Downloaded = rallyPoint.Downloaded,
                Left = rallyPoint.Left,
                Uploaded = rallyPoint.Uploaded,
                NumWant = numWant,
            };
            if (numWant > 0)
            {
                // get peers on this rally point and signaler
                var peers = ConnectedPeers.Where(o => o.InfoHash == rallyPoint.InfoHash).ToList();
                if (rallyPoint.BootStrapOnly && peers.Any())
                {
                    // when BootStrapOnly == true, only 1 connected peer is desired on this rally point signaler
                    // connections may still be accepted, but offers will not be sent out vai the server
                    numWant = 0;
                }
            }
            query.Offers = await GenerateOffers(rallyPoint, numWant);
            SendMessage(query);
        }
        void SendStoppedEvent(RallyPoint rallyPoint)
        {
            var query = new AnnounceQueryStopped
            {
                PeerId = PeerId,
                InfoHash = rallyPoint.InfoHash,
            };
            var sent = SendMessage(query);
            if (sent) rallyPoint.UpdateSignalerState(Url, "stopped");
        }
        void SendCompletedEvent(RallyPoint rallyPoint)
        {
            var query = new AnnounceQueryCompleted
            {
                PeerId = PeerId,
                InfoHash = rallyPoint.InfoHash,
                Downloaded = rallyPoint.Downloaded,
                Uploaded = rallyPoint.Uploaded,
            };
            var sent = SendMessage(query);
            if (sent) rallyPoint.UpdateSignalerState(Url, "completed");
        }
        async Task SendStartedEvent(RallyPoint rallyPoint)
        {
            var numWant = rallyPoint.NumWantNow;
            var query = new AnnounceQueryStarted
            {
                PeerId = PeerId,
                InfoHash = rallyPoint.InfoHash,
                Downloaded = rallyPoint.Downloaded,
                Left = rallyPoint.Left,
                Uploaded = rallyPoint.Uploaded,
                NumWant = numWant,
            };
            if (numWant > 0)
            {
                // get peers on this rally point and signaler
                var peers = ConnectedPeers.Where(o => o.InfoHash == rallyPoint.InfoHash).ToList();
                if (rallyPoint.BootStrapOnly && peers.Any())
                {
                    // when BootStrapOnly == true, only 1 connected peer is desired on this rally point signaler
                    // connections may still be accepted, but offers will not be sent out vai the server
                    numWant = 0;
                }
            }
            query.Offers = await GenerateOffers(rallyPoint, numWant);
            var sent = SendMessage(query);
            if (sent)
            {
                rallyPoint.UpdateSignalerState(Url, "started");
                if (query.Left == 0)
                {
                    // the server will mark it as completed so mark it here also so we don't send an unnecessary completed event
                    rallyPoint.UpdateSignalerState(Url, "completed");
                }
            }
        }
        /// <summary>
        /// Called when this instance is being disposed
        /// </summary>
        /// <param name="disposing"></param>
        void Dispose(bool disposing)
        {
            if (Disposed) return;
            Disposed = true;
            if (disposing)
            {
                DisposeSocket();
            }
        }
        /// <summary>
        /// Returns true if this instance has been disposed
        /// </summary>
        public bool Disposed { get; set; }
        /// <summary>
        /// Disposes this instance
        /// </summary>
        public void Dispose()
        {
            if (Disposed) return;
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        /// Finalizer
        ~RallySignaler() => Dispose(false);
        RallyPeer? GetPeerByOfferId(RallyPoint rallyPoint, string offerId, string remotePeerId, string remoteSignerKeyHex, bool isOffer)
        {
            var infoHash = rallyPoint.InfoHash;
            if (remotePeerId == PeerId) return null;
            RallyPeer? peer = null;
            if (string.IsNullOrEmpty(offerId))
            {
                return null;
            }
            if (!isOffer)
            {
                peer = Peers.FirstOrDefault(o => o.OfferId == offerId && o.InfoHash == infoHash);
                if (peer != null)
                {
                    if (peer.VerifyOwner(remotePeerId, remoteSignerKeyHex))
                    {
                        return peer;
                    }
                    if (!peer.Claimed)
                    {
                        // check for existing peer with this remote peer id and infohash. don't want duplicates.
                        var existingPeer = rallyPoint.ConnectingOrConnectedPeers.FirstOrDefault(o => o.RemotePeerId == remotePeerId);
                        if (existingPeer != null && existingPeer.SignalReceived)
                        {
                            // ignoring connection to peer we are already connected/connecting to on this rally point
                            JS.Log("ignoring answer connection to peer we are already connected/connecting to on this rally point", rallyPoint.InfoHashSource, remotePeerId, existingPeer.SignalerUrl, Url);
                            return null;
                        }
                        // check if this peer can claim this unclaimed RallyPeer
                        var numWantNow = rallyPoint.NumWantNow;
                        var allowed = !rallyPoint.PeersWanted.Any() || rallyPoint.PeersWanted.Contains(remoteSignerKeyHex) || rallyPoint.PeersWanted.Contains(remotePeerId);
                        var ignoreConnect = numWantNow == 0 || !allowed || PeerConnectionIgnore(infoHash, remotePeerId, remoteSignerKeyHex);
                        if (ignoreConnect)
                        {
                            // ignoring
                            JS.Log("ignoring answer ignoreConnect", rallyPoint.InfoHashSource, remotePeerId);
                            return null;
                        }
                        peer.Claim(remotePeerId, remoteSignerKeyHex);
                        return peer;
                    }
                    else
                    {
                        JS.Log("invalid remote id or info hash for this offer!!!!!!!!!!!!!!!!!!!!!!!!!!!", remotePeerId);
                    }
                }
            }
            else
            {
                var existingPeer = rallyPoint.ConnectingOrConnectedPeers.FirstOrDefault(o => o.RemotePeerId == remotePeerId);
                if (existingPeer != null && existingPeer.SignalReceived)
                {
                    // ignoring connection to peer we are already connected/connecting to on this rally point
                    JS.Log("ignoring offer connection to peer we are already connected/connecting to on this rally point", rallyPoint.InfoHashSource, remotePeerId, existingPeer.SignalerUrl, Url);
                    return null;
                }
                // check if this peer can claim a new RallyPeer
                var numWantNow = rallyPoint.NumWantNow;
                var allowed = !rallyPoint.PeersWanted.Any() || rallyPoint.PeersWanted.Contains(remoteSignerKeyHex) || rallyPoint.PeersWanted.Contains(remotePeerId);
                var ignoreConnect = numWantNow == 0 || !allowed || PeerConnectionIgnore(infoHash, remotePeerId, remoteSignerKeyHex);
                if (ignoreConnect)
                {
                    // ignoring
                    JS.Log("ignoring offer ignoreConnect", remotePeerId);
                    return null;
                }
                peer = new RallyPeer(rallyPoint, ServiceProvider, new SimplePeerOptions
                {
                    Initiator = false,
                    Trickle = RallyService.Trickle,
                    ObjectMode = false,
                    Config = RallyService.RTCConfiguration,
                })
                {
                    OfferId = offerId,
                    InfoHash = infoHash,
                    PeerId = PeerId,
                    SignalerUrl = Url,
                };
                peer.Claim(remotePeerId, remoteSignerKeyHex);
                AttachPeerHandlers(peer);
                Peers.Add(peer);
            }
            return peer;
        }
        /// <summary>
        /// Fires the OnPeerFilter event allowing subscribers the ability to cancel the connection
        /// </summary>
        /// <param name="infoHash"></param>
        /// <param name="remotePeerId"></param>
        /// <param name="remoteSignerKeyHex"></param>
        /// <returns></returns>
        bool PeerConnectionIgnore(string infoHash, string remotePeerId, string remoteSignerKeyHex)
        {
            var filterArgs = new PeerFilterEventArgs
            {
                InfoHash = infoHash,
                RemotePeerId = remotePeerId,
                RemoteSignerKeyHex = remoteSignerKeyHex
            };
            OnPeerFilter?.Invoke(filterArgs);
            return filterArgs.Ignore;
        }
        /// <summary>
        /// RallyPeer instances keyed on the offer id
        /// </summary>
        //Dictionary<string, RallyPeer> PeerOffers { get; } = new Dictionary<string, RallyPeer>();
        /// <summary>
        /// RallyPeer instances
        /// </summary>
        public List<RallyPeer> Peers { get; } = new List<RallyPeer>();
        /// <summary>
        /// RallyPeer instances that are connecting or connected
        /// </summary>
        public List<RallyPeer> ConnectingOrConnectedPeers => Peers.Where(o => o.Connecting || o.Connected).ToList();
        /// <summary>
        /// RallyPeer instances that are connecting
        /// </summary>
        public List<RallyPeer> ConnectingPeers => Peers.Where(o => o.Connecting).ToList();
        /// <summary>
        /// RallyPeer instances that are connected
        /// </summary>
        public List<RallyPeer> ConnectedPeers => Peers.Where(o => o.Connected).ToList();
        /// <summary>
        /// RallyPeer instances that are Ready
        /// </summary>
        public List<RallyPeer> ReadyPeers => Peers.Where(o => o.Ready && o.Connected).ToList();
        /// <summary>
        /// RallyPeer instances that are not claimed yet. These are generated offers that have been sent to the server to distribute to random peers.
        /// </summary>
        public List<RallyPeer> AwaitingPeers => Peers.Where(o => o.SignalerUrl == Url && o.AwaitingAnswer).ToList();
        /// <summary>
        /// Delegate type that allows filtering new connections
        /// </summary>
        /// <param name="args"></param>
        public delegate void PeerFilterDelegate(PeerFilterEventArgs args);
        /// <summary>
        /// Fired when a peer connection is about to occur, and allows cancelling the connection
        /// </summary>
        public event PeerFilterDelegate OnPeerFilter = default!;
        void DisposeUnclaimed(string infoHash)
        {
            var awaitingPeers = Peers.Where(o => o.InfoHash == infoHash && !o.Claimed).ToList();
            foreach (var p in awaitingPeers)
            {
                Peers.Remove(p);
                DetachPeerHandlers(p);
                p.Dispose();
            }
        }
        void DisposeInfoHashPeers(string infoHash)
        {
            var peers = Peers.Where(o => o.InfoHash == infoHash).ToList();
            foreach (var p in peers)
            {
                Peers.Remove(p);
                DetachPeerHandlers(p);
                p.Dispose();
            }
        }
        /// <summary>
        /// Generates offers for the given RallyPoint that will be sent to the signaler, and then<br/>
        /// it will send each one to a random peer.
        /// </summary>
        /// <param name="rallyPoint"></param>
        /// <param name="numWant">The number of offers to generate</param>
        /// <returns></returns>
        async Task<AnnounceWebRTCOffer[]> GenerateOffers(RallyPoint rallyPoint, int numWant)
        {
            string infoHash = rallyPoint.InfoHash;
            int count = numWant;
            DisposeUnclaimed(infoHash);
            // TODO - fix below to take into account remoteIds (if needed)
            var connectingOrConnectedPeerKeys = rallyPoint.ConnectingOrConnectedPeers.Select(o => o.RemoteSignerKeyHex).ToList();
            var targetKeys = rallyPoint.PeersWanted.Except(connectingOrConnectedPeerKeys).OrderBy(_ => rng.Next()).ToList();
            var maxTargetKeyCount = Math.Clamp(count, 10, 20);
            // don't send a ton of keys with the offer as it bloats it quickly
            if (targetKeys.Count > maxTargetKeyCount)
            {
                targetKeys = targetKeys.Take(maxTargetKeyCount).ToList();
            }
            var ret = new AnnounceWebRTCOffer[count];
            for (int i = 0; i < count; i++)
            {
                var peer = new RallyPeer(rallyPoint, ServiceProvider, new SimplePeerOptions
                {
                    Initiator = true,
                    Trickle = RallyService.Trickle,
                    ObjectMode = false,
                    Config = RallyService.RTCConfiguration,
                })
                {
                    InfoHash = infoHash,
                    SignalerUrl = Url,
                    PeerId = PeerId,
                };
                AttachPeerHandlers(peer);
                Peers.Add(peer);
                ret[i] = new AnnounceWebRTCOffer
                {
                    OfferId = peer.OfferId,
                    Offer = new RTCSessionDescription
                    {
                        Type = "offer",
                        Sdp = await SignalToSdp(await peer.GetInitialOffer(), targetKeys.ToArray()),
                    },
                };
            }
            return ret;
        }

        async Task ConnectToPeer(RallyPeer rallyPeer, RallyPoint rallyPoint, string remotePeerId, string remoteSignerHex)
        {
            // check for existing peer on this rally point with this peer (does not have to be on this signaler!)
            JS.Log(">> ConnectToPeer", remotePeerId == PeerId ? "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" : "", remotePeerId);
            if (remotePeerId == PeerId) return;
            var peer = rallyPoint.ConnectingOrConnectedPeers.FirstOrDefault(o => o.RemotePeerId == remotePeerId);
            if (peer != null)
            {
                // already exists
                JS.Log("<< ConnectToPeer 1");
                return;
            }
            if (peer == null)
            {
                peer = new RallyPeer(rallyPoint, ServiceProvider, new SimplePeerOptions
                {
                    Initiator = true,
                    Trickle = RallyService.Trickle,
                    ObjectMode = false,
                    Config = RallyService.RTCConfiguration,
                })
                {
                    InfoHash = rallyPoint.InfoHash,
                    SignalerUrl = Url,
                    PeerId = PeerId,
                };
                var sdpEncoded = await SignalToSdp(await peer.GetInitialOffer(), remotePeerId);
                AttachPeerHandlers(peer);
                peer.Claim(remotePeerId, remoteSignerHex);
                Peers.Add(peer);
                //SendMessage(MessageToPeer.FromSignal(peer.RemotePeerId, peer.PeerId, peer.InfoHash, peer.OfferId, "answer", sdpEncoded));
                JS.Log("<< ConnectToPeer 2");
                var sdpMessage = new RTCSessionDescription
                {
                    Type = "offer",
                    Sdp = sdpEncoded,
                };
                // use rallyPeer to relay the message
                try
                {
                    await rallyPeer.Run(() => HandleRelayedPeerOffer(Url, rallyPoint.InfoHash, peer.OfferId, sdpMessage, null!, null!));
                }
                catch (Exception ex)
                {
                    JS.Log("Untargeted Offer relay failed:", ex.ToString());
                }
            }
            JS.Log("<< ConnectToPeer 3");
        }
        void AttachPeerHandlers(RallyPeer peer)
        {
            peer.OnError += Peer_OnError;
            peer.OnSignal += Peer_OnSignal;
            peer.OnClose += Peer_OnClose;
            peer.OnConnect += Peer_OnConnect;
            peer.OnConnecting += Peer_OnConnecting;
            peer.OnRemoteConnectionsUpdated += Peer_OnRemoteConnectionsUpdated;
        }
        private void Peer_OnRemoteConnectionsUpdated(RallyPeer peer)
        {
            if (ConnectToPeersOnConnect)
            {
                _ = ConnectToPeers(peer);
            }
        }
        private void Peer_OnError(RallyPeer peer)
        {
            if (!peer.Connected)
            {
                JS.Log("Peer_OnClose", ConnectedPeers.Count, string.Join(", ", ConnectedPeers.Select(o => o.RemotePeerId)));
                if (Peers.Contains(peer))
                {
                    Peers.Remove(peer);
                    DetachPeerHandlers(peer);
                    OnPeerClose?.Invoke(peer);
                    peer.Dispose();
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public event Action<RallyPeer>? OnPeerConnect = default!;
        /// <summary>
        /// 
        /// </summary>
        public event Action<RallyPeer>? OnPeerClose = default!;
        /// <summary>
        /// 
        /// </summary>
        public event Action<RallyPeer>? OnPeerConnecting = default!;
        private void Peer_OnConnect(RallyPeer peer)
        {
            JS.Log("Peer_OnConnect", ConnectedPeers.Count, string.Join(", ", ConnectedPeers.Select(o => o.RemotePeerId)));
            OnPeerConnect?.Invoke(peer);
        }
        private void Peer_OnClose(RallyPeer peer)
        {
            JS.Log("Peer_OnClose", ConnectedPeers.Count, string.Join(", ", ConnectedPeers.Select(o => o.RemotePeerId)));
            if (Peers.Contains(peer))
            {
                Peers.Remove(peer);
                DetachPeerHandlers(peer);
                OnPeerClose?.Invoke(peer);
                peer.Dispose();
            }
        }
        void DetachPeerHandlers(RallyPeer peer)
        {
            peer.OnError -= Peer_OnError;
            peer.OnSignal -= Peer_OnSignal;
            peer.OnClose -= Peer_OnClose;
            peer.OnConnect -= Peer_OnConnect;
            peer.OnConnecting -= Peer_OnConnecting;
            peer.OnRemoteConnectionsUpdated -= Peer_OnRemoteConnectionsUpdated;
        }
        private async void Peer_OnSignal(RallyPeer peer, string signal)
        {
            if (string.IsNullOrEmpty(peer.RemotePeerId))
            {
                // no peer id set... 
                return;
            }
            try
            {
                var sdpEncoded = await SignalToSdp(signal, peer.RemotePeerId);
                var relayed = await RelayMessage(peer.RallyPoint, peer.OfferId, peer.PeerId, new[] { peer.RemotePeerId }, new RTCSessionDescription { Type = "answer", Sdp = sdpEncoded }, false);
                if (!relayed)
                {
                    SendMessage(MessageToPeer.FromSignal(peer.RemotePeerId, peer.PeerId, peer.InfoHash, peer.OfferId, "answer", sdpEncoded));
                }
            }
            catch (Exception ex)
            {
                JS.Log("Peer_OnSignal error:", ex.ToString());
            }
        }
        private void Peer_OnConnecting(RallyPeer peer)
        {
            OnPeerConnecting?.Invoke(peer);
        }
        internal void RemoveHash(string infoHash)
        {
            if (_RallyPoints.TryGetValue(infoHash, out var rallyPoint))
            {
                DisposeInfoHashPeers(infoHash);
                _RallyPoints.Remove(infoHash);
                SendStoppedEvent(rallyPoint);
                if (!_RallyPoints.Any())
                {
                    StartIdleDisconnectTimer();
                }
            }
        }
        internal void AddRallyPoint(RallyPoint rallyPoint)
        {
            if (!_RallyPoints.ContainsKey(rallyPoint.InfoHash))
            {
                StopIdleDisconnectTimer();
                _RallyPoints[rallyPoint.InfoHash] = rallyPoint;
                _ = Update(rallyPoint);
            }
        }
    }
}
