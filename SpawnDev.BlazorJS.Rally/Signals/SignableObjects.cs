namespace SpawnDev.BlazorJS.Rally.Signals
{
    /// <summary>
    /// ECDSA signature token and metadata.<br/>
    /// All properties are included except Token when the signature (token) is calculated.
    /// </summary>
    public class Signature
    {
        /// <summary>
        /// Signing algorithm name
        /// </summary>
        public string Alg { get; set; } = "";
        /// <summary>
        /// The generated signature
        /// </summary>
        public string Token { get; set; } = "";
        /// <summary>
        /// The public key of the signee
        /// </summary>
        public string PublicKey { get; set; } = "";
        /// <summary>
        /// When the token was signed
        /// </summary>
        public EpochDateTime TokenSigned { get; set; } = default!;
        /// <summary>
        /// If not null, this is when the token expires
        /// </summary>
        public EpochDateTime? TokenExpiration { get; set; }
        /// <summary>
        /// Claims specific to this signature
        /// </summary>
        public Dictionary<string, string> Claims { get; set; } = new Dictionary<string, string>();
    }
    /// <summary>
    /// A signable object
    /// </summary>
    public class SignedObject
    {
        /// <summary>
        /// ECDSA Signatures
        /// </summary>
        public List<Signature> Signatures { get; set; } = new List<Signature>();
        /// <summary>
        /// Claims
        /// </summary>
        public Dictionary<string, List<string>> Claims { get; set; } = new Dictionary<string, List<string>>();
        /// <summary>
        /// Get
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public string? GetClaimFirstOrDefault(string key) => GetClaims(key)?.FirstOrDefault();
        /// <summary>
        /// Adds a claim with the specified key and value if it does not already exist
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        public void AddClaim(string key, string value)
        {
            if (!Claims.TryGetValue(key, out var values))
            {
                values = new List<string>();
                Claims[key] = values;
            }
            var exists = values.Contains(value);
            if (!exists) values.Add(value);
        }
        /// <summary>
        /// Removes the claim with the specified key and value
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        public void RemoveClaim(string key, string value)
        {
            if (Claims.TryGetValue(key, out var values))
            {
                Claims[key] = values.Where(o => o != value).ToList();
                if (!Claims[key].Any())
                {
                    Claims.Remove(key);
                }
            }
        }
        /// <summary>
        /// Removes all claims with the given key
        /// </summary>
        /// <param name="key"></param>
        public void RemoveClaims(string key)
        {
            if (Claims.ContainsKey(key))
            {
                Claims.Remove(key);
            }
        }
        /// <summary>
        /// Returns true if the claim key exists
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsClaim(string key) => Claims.ContainsKey(key);
        /// <summary>
        /// Returns true if the claim exists
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool ContainsClaim(string key, string value) => GetClaims(key)?.Contains(value) ?? false;
        /// <summary>
        /// Returns a list of claim values with the specified key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public List<string>? GetClaims(string key) => Claims?.TryGetValue(key, out var values) ?? false ? values : null;
    }
    /// <summary>
    /// A signable object with a value of type T
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class SignedObject<T> : SignedObject
    {
        /// <summary>
        /// Value
        /// </summary>
        public T Value { get; set; } = default!;
    }
}
