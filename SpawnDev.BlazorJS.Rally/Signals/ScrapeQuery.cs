using System.Text.Json.Serialization;

namespace SpawnDev.BlazorJS.Rally.Signals
{
    public class ScrapeQuery : SignalerMessage
    {
        /// <inheritdoc/>
        [JsonPropertyName("action")]
        public override string Action { get; set; } = "scrape";


        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("info_hash")]
        public string[]? InfoHash { get; set; }
    }
}
