using System.Text.Json.Serialization;

namespace SpawnDev.BlazorJS.Rally.Signals
{
    public class AnnounceQueryCompleted : AnnounceQuery
    {
        /// <summary>
        /// Event<br/>
        /// - null<br/>
        /// - started<br/>
        /// - completed<br/>
        /// - stopped<br/>
        /// </summary>
        [JsonPropertyName("event")]
        public string Event { get; set; } = "completed";
        /// <summary>
        /// 
        /// </summary>
        [JsonPropertyName("left")]
        public int Left { get; set; } = 0;
        /// <inheritdoc/>
        [JsonPropertyName("numwant")]
        public override int NumWant { get; set; } = 50;
    }
}
