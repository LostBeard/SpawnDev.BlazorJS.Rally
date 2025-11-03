using SpawnDev.BlazorJS.WebWorkers;

namespace SpawnDev.BlazorJS.Rally.Signals
{
    public class RallyPeerAuthService
    {
        public string Id { get; } = Guid.NewGuid().ToString();
        public RallyPeerAuthService()
        {
            Console.WriteLine($"RallyPeerAuthService created {Id}");
        }
        [RemoteCallable]
        public static void ConsoleLog(string msg, [FromServices] RallyPeerAuthService RallyPeerAuthService = null!, [FromLocal] RallyPeer peer = null!)
        {
            Console.WriteLine($"ConsoleLog: {RallyPeerAuthService.Id} {peer.RemotePeerId} {msg}");
        }
    }
}
