using System.Text.Json.Serialization;

namespace SpawnDev.BlazorJS.Rally.Signals
{
    public class SignalerMessage
    {
        /// <summary>
        /// The message action
        /// </summary>
        [JsonPropertyName("action")]
        public virtual string Action { get; set; } = default!;
    }
}
