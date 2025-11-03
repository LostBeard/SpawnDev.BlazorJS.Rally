using System.ComponentModel.DataAnnotations;

namespace SpawnDev.BlazorJS.Rally
{
    /// <summary>
    /// Represents the identity of a device in the RallyPeer network.
    /// </summary>
    public class DeviceIdentity
    {
        /// <summary>
        /// device name, not guaranteed to be unique
        /// </summary>
        public string DeviceName { get; set; }
        /// <summary>
        /// public signing key
        /// </summary>
        public string Sign { get; init; }
        /// <summary>
        /// public encryption key
        /// </summary>
        public string Encrypt { get; init; }
        /// <summary>
        /// Simple crc of the encrypt public key spki exported bytes<br/>
        /// Cannot be relied on for uniqueness but is useful IDing in small groups
        /// </summary>
        public string? EncryptHash { get; init; }
        /// <summary>
        /// instance id
        /// </summary>
        public required string InstanceId { get; init; }
        /// <summary>
        /// user agent (application dependent)
        /// </summary>
        public string? UserAgent { get; init; }
        /// <summary>
        /// Simple crc of the signing public key spki exported bytes<br/>
        /// Cannot be relied on for uniqueness but is useful IDing in small groups
        /// </summary>
        public string? SignHash { get; init; }
    }
}
