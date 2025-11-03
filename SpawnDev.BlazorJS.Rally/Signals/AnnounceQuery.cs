using System.Text.Json.Serialization;

namespace SpawnDev.BlazorJS.Rally.Signals
{
    public class AnnounceQuery : SignalerMessage
    {
        /// <inheritdoc/>
        [JsonPropertyName("action")]
        public override string Action { get; set; } = "announce";
        /// <summary>
        /// The info hash being queried
        /// </summary>
        [JsonConverter(typeof(CharStringHexStringConverter))]
        [JsonPropertyName("info_hash")]
        public string InfoHash { get; set; } = default!;
        /// <summary>
        /// The peer id of the sender<br/>
        /// </summary>
        [JsonPropertyName("peer_id")]
        public string PeerId { get; set; } = default!;
        /// <summary>
        /// Gets or sets the number of peers wanted
        /// </summary>
        [JsonPropertyName("numwant")]
        public virtual int NumWant { get; set; } = 5;
        /// <summary>
        /// 
        /// </summary>
        [JsonPropertyName("uploaded")]
        public virtual long Uploaded { get; set; }
        /// <summary>
        /// 
        /// </summary>
        [JsonPropertyName("downloaded")]
        public virtual long Downloaded { get; set; }
    }
}
