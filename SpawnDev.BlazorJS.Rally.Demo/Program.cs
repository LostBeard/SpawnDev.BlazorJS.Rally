using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using SpawnDev.BlazorJS;
using SpawnDev.BlazorJS.JSObjects.WebRTC;
using SpawnDev.BlazorJS.Rally;
using SpawnDev.BlazorJS.Rally.Demo;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
// Add SpawnDev.BlazorJS interop
builder.Services.AddBlazorJSRuntime(out var JS);
// Add and configure RallyService
builder.Services.AddRallySingleton(RallyService =>
{
    // Add signalers
    RallyService.SignalerUrls.AddRange(new string[]
    {
#if DEBUG && false
        "ws://localhost:6565",
#else
        "wss://tracker.files.fm:7073/announce",
        //"wss://tracker.webtorrent.dev",
        //"wss://tracker.ghostchu-services.top:443/announce",
        //"wss://tracker.btorrent.xyz",
        //"wss://tracker.openwebtorrent.com",
#endif
    });
    RallyService.RTCConfiguration = new RTCConfiguration
    {
        IceServers = [
            new RTCIceServer
            {
                Urls = new []
                {
                    "stun:stun.l.google.com:19302",
                    "stun:global.stun.twilio.com:3478",
                }
            }
        ],
        SdpSemantics = "unified-plan"
    };
});

// Add dom objects if running in a window
if (JS.IsWindow)
{
    builder.RootComponents.Add<App>("#app");
    builder.RootComponents.Add<HeadOutlet>("head::after");
}
// Start
var host = await builder.Build().StartBackgroundServices();
#if DEBUG

#endif
// Run app using BlazorJSRunAsync
await host.BlazorJSRunAsync();
