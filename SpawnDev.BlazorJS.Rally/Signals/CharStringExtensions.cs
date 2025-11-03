namespace SpawnDev.BlazorJS.Rally.Signals
{
    /// <summary>
    /// Adds extensions that aids working with char strings
    /// </summary>
    public static class CharStringExtensions
    {
        /// <summary>
        /// Creates a simple checksum by folding the input byte array into a smaller byte array of the specified length.
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static byte[] SimpleCrc(this byte[] hash, int length = 8)
        {
            if (hash.Length < length) return hash;
            var hashLength = hash.Length;
            var ret = new byte[length];
            for (var i = 0; i < hashLength; i++)
            {
                var n = i % length;
                ret[n] = (byte)(hash[i] + ret[n]);
            }
            return ret;
        }
        /// <summary>
        /// Converts a byte array to a hex string
        /// </summary>
        /// <param name="data"></param>
        /// <param name="toLower"></param>
        /// <returns></returns>
        public static string ToHexString(this byte[] data, bool toLower = true) => toLower ? Convert.ToHexString(data).ToLowerInvariant() : Convert.ToHexString(data);
        /// <summary>
        /// Converts a hex string to a byte array
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string ToCharString(this byte[] data) => string.Join("", data.Select(o => (char)o));
        /// <summary>
        /// Converts a char string to a byte array
        /// </summary>
        /// <param name="charString"></param>
        /// <returns></returns>
        public static byte[] ToCharBytes(this string charString) => charString.Select(o => (byte)o).ToArray();
        /// <summary>
        /// Converts a char string to a hex string
        /// </summary>
        /// <param name="charString"></param>
        /// <param name="toLower"></param>
        /// <returns></returns>
        public static string CharStringToHexString(this string? charString, bool toLower = true) => charString == null ? null! : charString.Select(o => (byte)o).ToArray().ToHexString(toLower);
        /// <summary>
        /// Converts a hex string to a char string
        /// </summary>
        /// <param name="hexString"></param>
        /// <returns></returns>
        public static string HexStringToCharString(this string? hexString) => hexString == null ? null! : Convert.FromHexString(hexString).ToCharString();
    }
}
