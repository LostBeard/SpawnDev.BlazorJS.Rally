using Microsoft.Extensions.DependencyInjection;
using SpawnDev.BlazorJS.JSObjects;
using SpawnDev.BlazorJS.JSObjects.WebRTC;
using SpawnDev.BlazorJS.MessagePack;
using SpawnDev.BlazorJS.Rally.Signals;
using SpawnDev.BlazorJS.SimplePeer;
using SpawnDev.BlazorJS.Toolbox;
using SpawnDev.BlazorJS.WebWorkers;
using System.Security.Claims;
using Array = SpawnDev.BlazorJS.JSObjects.Array;

namespace SpawnDev.BlazorJS.Rally
{
    public enum RemoteConnectionInfosUpdateType
    {
        Full,
        Added,
        Removed,
    }
    public class ConnectionInfo
    {
        public string PeerId { get; init; }
        public string SignerKeyHex { get; init; }
        public string SignalerUrl { get; init; }
    }
    /// <summary>
    /// Client and server implementation for remotely calling .Net methods using SimplePeer
    /// </summary>
    public class RallyPeer : RemoteDispatcher, IDisposable
    {
        /// <summary>
        /// Once claimed this is a unique id that no other connect RallyPeer will have.<br/>
        /// AS the RemotePeerId is part of this id, this id will be unique to this specific connection
        /// </summary>
        //public string InstanceId => !Claimed ? "" : $"{InfoHash}|{RemoteSignerKeyHex}|{RemotePeerId}";
        /// <summary>
        /// Gets the unique identifier for the offer.
        /// </summary>
        public string OfferId { get; init; } = "";
        /// <summary>
        /// Swarm peer id.<br/>
        /// Generated when the RallyPeer is created.<br/>
        /// Not guaranteed to be unique.
        /// </summary>
        public string PeerId { get; init; } = "";
        /// <summary>
        /// The rally point info hash
        /// </summary>
        public string InfoHash { get; init; } = "";
        /// <summary>
        /// The signaler url this peer is using
        /// </summary>
        public string SignalerUrl { get; init; } = "";
        /// <summary>
        /// The remote peer id once known.<br/>
        /// This is the id  the signaler uses to identify the peer
        /// </summary>
        public string RemotePeerId { get; private set; } = "";
        /// <summary>
        /// Returns true if a remote peer id has been set indicating this web peer has been claimed by that peer.
        /// </summary>
        public bool Claimed { get; private set; }
        /// <summary>
        /// Returns true if the remote peer id and the signer key match this web peer's current state
        /// </summary>
        /// <param name="remotePeerId"></param>
        /// <param name="remoteSignerKeyHex"></param>
        /// <returns></returns>
        public bool VerifyOwner(string remotePeerId, string remoteSignerKeyHex)
        {
            return RemotePeerId == remotePeerId && RemoteSignerKeyHex == remoteSignerKeyHex;
        }
        /// <summary>
        /// Attempt to claim this RallyPeer
        /// </summary>
        /// <param name="remotePeerId"></param>
        /// <param name="remoteSignerKeyHex"></param>
        /// <returns></returns>
        public bool Claim(string remotePeerId, string remoteSignerKeyHex)
        {
            if (Claimed) return false;
            Claimed = true;
            RemotePeerId = remotePeerId;
            RemoteSignerKeyHex = remoteSignerKeyHex;
            if (!Connected && !Connecting)
            {
                Connecting = true;
                Async.Run(async () =>
                {
                    await Task.Delay(15000);
                    if (!IsDisposed && Connecting && !Connected)
                    {
                        JS.Log("RallyPeer connect timeout");
                        OnError?.Invoke(this);
                    }
                });
                OnConnecting?.Invoke(this);
            }
            return true;
        }
        /// <summary>
        /// The remote peer public ECDSA key once known
        /// </summary>
        public string RemoteSignerKeyHex { get; private set; } = "";
        /// <summary>
        /// Returns true if awaiting an offer answer
        /// </summary>
        public bool AwaitingAnswer => !SignalReceived && Initiator;
        /// <summary>
        /// Returns true if a signal has been received
        /// </summary>
        public bool SignalReceived { get; private set; }
        /// <summary>
        /// Returns true if awaiting an offer
        /// </summary>
        public bool AwaitingOffer => string.IsNullOrEmpty(RemotePeerId) && !Initiator;
        /// <summary>
        /// Returns true if this web peer is the initiator
        /// </summary>
        public bool Initiator { get; private set; }
        /// <summary>
        /// Returns true if connected
        /// </summary>
        public bool Connected { get; private set; }
        /// <summary>
        /// Invoked when a previously connected peer connection is closed.<br/>
        /// This is unlike SimplePeer.OnClose which will fire even if a connection was not established.
        /// </summary>
        public event Action<RallyPeer> OnClose = default!;
        /// <summary>
        /// Invoked when SimplePeer.OnError event fires.<br/>
        /// This event will fire if a connection fails to be established
        /// </summary>
        public event Action<RallyPeer> OnError = default!;
        /// <summary>
        /// Invoked when SimplePeer.OnConnect event fires
        /// </summary>
        public event Action<RallyPeer> OnConnect = default!;
        /// <summary>
        /// Invoked when the SimplePeer has a signal to send to the remote SimplePeer via a signaler
        /// </summary>
        public event Action<RallyPeer, string> OnSignal = default!;
        /// <summary>
        /// Passes the signal message from the signaler interface to SimplePeer
        /// </summary>
        /// <param name="signalJson"></param>
        public void Signal(string signalJson)
        {
            if (Connection == null) return;
            if (!Claimed)
            {
                JS.Log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                return;
            }
            if (!SignalReceived)
            {
                SignalReceived = true;
            }
            Connection.Signal(JSON.Parse(signalJson)!);
        }
        /// <summary>
        /// The underlying SimplePeer
        /// </summary>
        public SimplePeer.SimplePeer Connection { get; protected set; }
        /// <summary>
        /// The RallyPoint this RallyPeer is connected to
        /// </summary>
        public RallyPoint RallyPoint { get; }
        /// <inheritdoc/>
        public RallyPeer(RallyPoint rallyPoint, IServiceProvider serviceProvider, SimplePeer.SimplePeer simplePeer) : base(serviceProvider)
        {
            RallyPoint = rallyPoint;
            DeviceIdentityService = serviceProvider.GetRequiredService<DeviceIdentityService>();
            Connection = simplePeer;
            if (Connection.Initiator) OfferId = System.Security.Cryptography.RandomNumberGenerator.GetBytes(20).ToHexString();
            AttachHandlers();
        }
        DeviceIdentityService DeviceIdentityService;
        /// <inheritdoc/>
        public RallyPeer(RallyPoint rallyPoint, IServiceProvider serviceProvider, SimplePeerOptions simplePeerOptions) : base(serviceProvider)
        {
            RallyPoint = rallyPoint;
            DeviceIdentityService = serviceProvider.GetRequiredService<DeviceIdentityService>();
            this.simplePeerOptions = simplePeerOptions;
            simplePeerOptions.ObjectMode = null;
            Connection = new SimplePeer.SimplePeer(simplePeerOptions);
            if (Connection.Initiator)
            {
                OfferId = System.Security.Cryptography.RandomNumberGenerator.GetBytes(20).ToHexString();
                offerTcs = new TaskCompletionSource<string>();
            }
            AttachHandlers();
        }
        /// <inheritdoc/>
        public RallyPeer(RallyPoint rallyPoint, IServiceProvider serviceProvider, bool initiator, bool trickle = false, RTCConfiguration? rtcConfig = null) : base(serviceProvider)
        {
            RallyPoint = rallyPoint;
            DeviceIdentityService = serviceProvider.GetRequiredService<DeviceIdentityService>();
            simplePeerOptions = new SimplePeerOptions
            {
                Initiator = initiator,
                Trickle = trickle,
                Config = rtcConfig,
            };
            Connection = new SimplePeer.SimplePeer(simplePeerOptions);
            if (Connection.Initiator)
            {
                OfferId = System.Security.Cryptography.RandomNumberGenerator.GetBytes(20).ToHexString();
                offerTcs = new TaskCompletionSource<string>();
            }
            AttachHandlers();
        }
        TaskCompletionSource<string>? offerTcs = null;
        SimplePeerOptions? simplePeerOptions = null;
        /// <summary>
        /// Recreate
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public async Task<string> GetInitialOffer()
        {
            if (!Connection.Initiator || offerTcs == null) throw new InvalidOperationException("Only the initiator can create an initial offer");
            return await offerTcs.Task;
        }
        /// <summary>
        /// Disposes resources
        /// </summary>
        public override void Dispose()
        {
            if (IsDisposed) return;
            Connecting = false;
            if (Connected)
            {
                Connected = false;
                OnClose?.Invoke(this);
            }
            if (Connection != null)
            {
                Connection.OnSignal -= SimplePeer_OnSignal;
                Connection.OnConnect -= SimplePeer_OnConnect;
                Connection.OnClose -= SimplePeer_OnClose;
                Connection.OnError -= SimplePeer_OnError;
                Connection.RemoveListener<Uint8Array>("data", DataConnection_OnData);
                Connection.Destroy();
                Connection.Dispose();
            }
            RallyPoint.OnPeerConnect -= RallyPoint_OnPeerConnect;
            RallyPoint.OnPeerClose -= RallyPoint_OnPeerClose;
            base.Dispose();
        }
        [RemoteCallable]
        protected async Task HandleRemoteConnectionInfosUpdate(ConnectionInfo[] connectionInfos, RemoteConnectionInfosUpdateType updateType, [FromLocal] RallyPeer rallyPeer)
        {
            try
            {
                var fireEvent = false;
                JS.Log("updateType", updateType.ToString());
                switch (updateType)
                {
                    case RemoteConnectionInfosUpdateType.Full:
                        _ConnectionInfos.Clear();
                        foreach (var connInfo in connectionInfos)
                        {
                            _ConnectionInfos[connInfo.PeerId] = connInfo;
                        }
                        fireEvent = true;
                        break;
                    case RemoteConnectionInfosUpdateType.Removed:
                        foreach (var connInfo in connectionInfos)
                        {
                            if (_ConnectionInfos.ContainsKey(connInfo.PeerId))
                            {
                                _ConnectionInfos.Remove(connInfo.PeerId);
                                fireEvent = true;
                            }
                        }
                        break;
                    case RemoteConnectionInfosUpdateType.Added:
                        foreach (var connInfo in connectionInfos)
                        {
                            if (_ConnectionInfos.TryGetValue(connInfo.PeerId, out var existingInfo))
                            {
                                var changed = existingInfo.SignerKeyHex != connInfo.SignerKeyHex;
                                if (changed) fireEvent = true;
                            }
                            else
                            {
                                fireEvent = true;
                            }
                            _ConnectionInfos[connInfo.PeerId] = connInfo;
                        }
                        break;
                }
                if (fireEvent)
                {
                    JS.Log($"Peer connections:", RemotePeerId, " - ", string.Join(", ", _ConnectionInfos.Keys));
                    OnRemoteConnectionsUpdated?.Invoke(this);
                }
            }
            catch (Exception ex)
            {
                JS.Log("HandleRemoteConnectionInfosUpdate error:", ex.ToString());
            }
        }
        Dictionary<string, ConnectionInfo> _ConnectionInfos = new Dictionary<string, ConnectionInfo>();
        /// <summary>
        /// 
        /// </summary>
        public List<ConnectionInfo> ConnectionInfos => _ConnectionInfos.Values.ToList();
        /// <summary>
        /// 
        /// </summary>
        public event Action<RallyPeer> OnRemoteConnectionsUpdated = default!;
        /// <summary>
        /// Initial offer generated by the initiator peer
        /// </summary>
        public string? Offer { get; private set; }
        private void SimplePeer_OnSignal(JSObject data)
        {
            var signalJson = JSON.Stringify(data);
            if (Initiator && string.IsNullOrEmpty(Offer))
            {
                // the Initiator's first offer is captured and assigned to Offer
                Offer = signalJson;
                if (offerTcs != null && !offerTcs.Task.IsCompleted)
                {
                    offerTcs.SetResult(signalJson);
                }
            }
            else
            {
                OnSignal?.Invoke(this, signalJson);
            }
        }
        /// <summary>
        /// Returns true if the peer is in the process of connecting
        /// </summary>
        public bool Connecting { get; private set; } = false;
        /// <summary>
        /// Fires when connecting has started
        /// </summary>
        public event Action<RallyPeer> OnConnecting = default!;
        private void AttachHandlers()
        {
            Initiator = Connection.Initiator;
            Connection.OnSignal += SimplePeer_OnSignal;
            Connection.OnConnect += SimplePeer_OnConnect;
            Connection.OnClose += SimplePeer_OnClose;
            Connection.OnError += SimplePeer_OnError;
            Connection.On<Uint8Array>("data", DataConnection_OnData);

            RallyPoint.OnPeerConnect += RallyPoint_OnPeerConnect;
            RallyPoint.OnPeerClose += RallyPoint_OnPeerClose;
        }
        private void Send(object?[] args)
        {
            if (Connection == null || Connection.IsWrapperDisposed || Connection.Destroyed)
            {
                return;
            }
            using var uint8Array = MessagePackSerializer.Encode(args);
            Connection!.Write(uint8Array);
        }
        private void DataConnection_OnData(Uint8Array data)
        {
            //if (Connecting || !Connected)
            //{
            //    JS.Log("!!!!!!!!!!!!!!!!!!!!!!!!!!!        this actually happens       !!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            //    SimplePeer_OnConnect();
            //}
            var msg = MessagePackSerializer.Decode<Array>(data);
            data.Dispose();
            _ = HandleCall(msg);
        }
        private void SimplePeer_OnConnect()
        {
            JS.Log("SimplePeer_OnConnect");
            SendReadyFlag();
            if (Connecting && !Connected)
            {
                _ = PostConnect();
            }
        }
        async Task PostConnect()
        {
            try
            {
                await WhenReady.WaitAsync(TimeSpan.FromSeconds(10));
            }
            catch (Exception ex)
            {
                // connect timed out
                Connection.Destroy();
                var nmt = true;
                return;
            }
            if (Connected || !Connecting || IsDisposed || Connection == null || Connection.IsWrapperDisposed || Connection.Destroying || Connection.Destroyed)
            {
                return;
            }
            var existingPeers = RallyPoint.ConnectingOrConnectedPeers.Where(o => o != this && o.RemotePeerId == RemotePeerId).ToList();
            if (existingPeers.Any(o => o.Connected))
            {
                JS.Log("There is already another connected peer connection to the same peer on the same rally point, cancelling this one");
                Connection.Destroy();
                return;
            }
            var connecting = existingPeers.Where(o => o.Connecting).ToList();
            foreach (var c in connecting)
            {
                JS.Log("Cancelling another connection now that this is connected");
                c.Connection.Destroy();
            }
            Connecting = false;
            Connected = true;
            OnConnect?.Invoke(this);
            try
            {
                await UpdateRemoteConnectionListFull();
            }
            catch (Exception ex)
            {
                var nmt = true;
            }
        }
        async Task UpdateRemoteConnectionListFull()
        {
            var connectionInfos = RallyPoint.ConnectedPeers.Where(o => o != this && o.SignalerUrl == SignalerUrl).Select(o => new ConnectionInfo
            {
                PeerId = o.RemotePeerId,
                SignerKeyHex = o.RemoteSignerKeyHex,
                SignalerUrl = SignalerUrl,
            }).ToArray();
            try
            {
                await Run(() => HandleRemoteConnectionInfosUpdate(connectionInfos, RemoteConnectionInfosUpdateType.Full, null!));
            }
            catch (Exception ex)
            {
                var nmt = ex.ToString();
            }
        }
        async Task UpdateRemoteConnectionListRemoved(params ConnectionInfo[] removed)
        {
            if (removed == null || !removed.Any()) return;
            try
            {
                await Run(() => HandleRemoteConnectionInfosUpdate(removed, RemoteConnectionInfosUpdateType.Removed, null!));
            }
            catch { }
        }
        async Task UpdateRemoteConnectionListAdded(params ConnectionInfo[] added)
        {
            if (added == null || !added.Any()) return;
            try
            {
                await Run(() => HandleRemoteConnectionInfosUpdate(added, RemoteConnectionInfosUpdateType.Added, null!));
            }
            catch { }
        }
        private void RallyPoint_OnPeerClose(RallyPoint rallyPoint, RallyPeer peer)
        {
            if (Connected)
            {
                if (peer == this) return;
                _ = UpdateRemoteConnectionListRemoved(new ConnectionInfo { PeerId = peer.RemotePeerId, SignerKeyHex = peer.RemoteSignerKeyHex, SignalerUrl = SignalerUrl });
            }
        }
        private void RallyPoint_OnPeerConnect(RallyPoint rallyPoint, RallyPeer peer)
        {
            if (Connected)
            {
                if (peer == this) return;
                _ = UpdateRemoteConnectionListAdded(new ConnectionInfo { PeerId = peer.RemotePeerId, SignerKeyHex = peer.RemoteSignerKeyHex, SignalerUrl = SignalerUrl });
            }
        }
        private void SimplePeer_OnError(NodeError nodeError)
        {
            JS.Log("SimplePeer_OnError", nodeError.Message);
            //ResetWhenReady();
            OnError?.Invoke(this);
        }
        private void SimplePeer_OnClose()
        {
            JS.Log("SimplePeer_OnClose");
            ResetWhenReady();
            if (Connecting)
            {
                Connecting = false;
            }
            if (Connected)
            {
                Connected = false;
                OnClose?.Invoke(this);
            }
        }
        /// <summary>
        /// Send call data to the remote peer
        /// </summary>
        /// <param name="args"></param>
        protected override void SendCall(object?[] args) => Send(args);
    }
}
