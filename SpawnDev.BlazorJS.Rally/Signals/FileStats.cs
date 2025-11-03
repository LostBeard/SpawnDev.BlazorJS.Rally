using System.Text.Json.Serialization;

namespace SpawnDev.BlazorJS.Rally.Signals
{
    public class FileStats
    {
        [JsonPropertyName("complete")]
        public int Complete { get; set; }
        [JsonPropertyName("incomplete")]
        public int Incomplete { get; set; }
        [JsonPropertyName("downloaded")]
        public int Downloaded { get; set; }
    }
}
