using SpawnDev.BlazorJS.JSObjects.WebRTC;
using System.Text.Json.Serialization;

namespace SpawnDev.BlazorJS.Rally.Signals
{
    public class MessageToPeer : SignalerMessage
    {
        public static MessageToPeer FromSignal(string toPeerId, string fromPeerId, string infoHash, string offerId, string type, string signal) =>
            new MessageToPeer(toPeerId, fromPeerId, infoHash, offerId, type, signal);
        //
        public MessageToPeer() { }
        public MessageToPeer(string toPeerId, string fromPeerId, string infoHash, string offerId)
        {
            ToPeerId = toPeerId;
            PeerId = fromPeerId;
            InfoHash = infoHash;
            OfferId = offerId;
        }
        public MessageToPeer(string toPeerId, string fromPeerId, string infoHash, string offerId, RTCSessionDescription answer)
        {
            ToPeerId = toPeerId;
            PeerId = fromPeerId;
            InfoHash = infoHash;
            OfferId = offerId;
            Answer = answer;
        }
        public MessageToPeer(string toPeerId, string fromPeerId, string infoHash, string offerId, string type, string signal)
        {
            ToPeerId = toPeerId;
            PeerId = fromPeerId;
            InfoHash = infoHash;
            OfferId = offerId;
            Answer = new RTCSessionDescription { Type = type, Sdp = signal };
        }

        [JsonPropertyName("action")]
        public override string Action { get; set; } = "announce";

        [JsonConverter(typeof(CharStringHexStringConverter))]
        [JsonPropertyName("info_hash")]
        public string InfoHash { get; set; }

        [JsonConverter(typeof(CharStringHexStringConverter))]
        [JsonPropertyName("offer_id")]
        public string OfferId { get; set; }

        [JsonPropertyName("peer_id")]
        public string PeerId { get; set; }

        [JsonPropertyName("to_peer_id")]
        public string ToPeerId { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("answer")]
        public RTCSessionDescription? Answer { get; set; }
    }
}
