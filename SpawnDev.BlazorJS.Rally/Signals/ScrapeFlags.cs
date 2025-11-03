using System.Text.Json.Serialization;

namespace SpawnDev.BlazorJS.Rally.Signals
{
    public class ScrapeFlags
    {
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("min_request_interval")]
        public int? MinRequestInterval { get; set; }
    }
}
