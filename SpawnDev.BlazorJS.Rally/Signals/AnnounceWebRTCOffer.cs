using SpawnDev.BlazorJS.JSObjects.WebRTC;
using System.Text.Json.Serialization;

namespace SpawnDev.BlazorJS.Rally.Signals
{
    public class AnnounceWebRTCOffer
    {
        /// <summary>
        /// Offer id
        /// </summary>
        [JsonConverter(typeof(CharStringHexStringConverter))]
        [JsonPropertyName("offer_id")]
        public string OfferId { get; set; }
        /// <summary>
        /// Offer
        /// </summary>
        [JsonPropertyName("offer")]
        public RTCSessionDescription Offer { get; set; }
    }
}
