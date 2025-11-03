using System.Text.Json.Serialization;

namespace SpawnDev.BlazorJS.Rally.Signals
{
    public class AnnounceQueryUpdate : AnnounceQuery
    {
        /// <summary>
        /// 
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("left")]
        public long? Left { get; set; }
        /// <summary>
        /// Peer offers from the sender
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("offers")]
        public AnnounceWebRTCOffer[]? Offers { get; set; }
    }
}
