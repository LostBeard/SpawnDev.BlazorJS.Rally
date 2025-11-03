using SpawnDev.BlazorJS.JSObjects.WebRTC;
using System.Text.Json.Serialization;

namespace SpawnDev.BlazorJS.Rally.Signals
{
    public class SignalerMessageResponseMessage : SignalerMessage
    {
        /// <summary>
        /// This value is set if a request failed
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("failure_reason")]
        public string? FailureReason { get; set; }

        /// <summary>
        /// The message action, should be announce for this type
        /// </summary>
        [JsonPropertyName("action")]
        public override string Action { get; set; }

        /// <summary>
        /// Scrape result files
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("files")]
        public Dictionary<string, FileStats>? Files { get; set; }

        /// <summary>
        /// Scrape result flags
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("flags")]
        public ScrapeFlags? Flags { get; set; }

        /// <summary>
        /// The swarm info hash
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonConverter(typeof(CharStringHexStringConverter))]
        [JsonPropertyName("info_hash")]
        public string? InfoHash { get; set; }

        /// <summary>
        /// The number of complete peers
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("complete")]
        public int? Complete { get; set; }

        /// <summary>
        /// The number of incomplete peers
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("incomplete")]
        public int? Incomplete { get; set; }

        /// <summary>
        /// The number of seconds the client should wait to update
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("interval")]
        public int? Interval { get; set; }

        /// <summary>
        /// The offer id this message is related to
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonConverter(typeof(CharStringHexStringConverter))]
        [JsonPropertyName("offer_id")]
        public string? OfferId { get; set; }

        /// <summary>
        /// The peer who sent this message, if it is a message from a peer
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("peer_id")]
        public string? PeerId { get; set; }

        /// <summary>
        /// Answer to our offer from a peer
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("answer")]
        public RTCSessionDescription? Answer { get; set; }

        /// <summary>
        /// Offer from a peer
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("offer")]
        public RTCSessionDescription? Offer { get; set; }
    }
}
