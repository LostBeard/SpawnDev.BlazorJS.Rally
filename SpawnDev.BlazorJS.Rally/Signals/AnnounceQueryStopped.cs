using System.Text.Json.Serialization;

namespace SpawnDev.BlazorJS.Rally.Signals
{
    public class AnnounceQueryStopped : AnnounceQuery
    {
        /// <summary>
        /// Event<br/>
        /// - null<br/>
        /// - started<br/>
        /// - completed<br/>
        /// - stopped<br/>
        /// </summary>
        [JsonPropertyName("event")]
        public string? Event { get; set; } = "stopped";
        /// <inheritdoc/>
        [JsonPropertyName("numwant")]
        public override int NumWant { get; set; } = 50;
    }
}
