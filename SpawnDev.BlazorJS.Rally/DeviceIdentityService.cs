using SpawnDev.BlazorJS.JSObjects;
using SpawnDev.BlazorJS.MessagePack;
using SpawnDev.BlazorJS.Rally.Signals;
using SpawnDev.BlazorJS.Toolbox;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SpawnDev.BlazorJS.Rally
{
    /// <summary>
    /// Creates and manages a device identity for this browser/device<br/>
    /// </summary>
    public class DeviceIdentityService : IAsyncBackgroundService
    {
        EcdsaParams DefaultEcdsaParams = new EcdsaParams { Hash = "SHA-512" };
        static string ECDHNamedCurve = "P-521";
        static string ECDSANamedCurve = "P-521";
        Cache Cache { get; set; }
        Lazy<string> _UserAgent;
        /// <summary>
        /// Device identity
        /// </summary>
        public DeviceIdentity Identity { get; private set; }
        /// <summary>
        /// Device user agent string
        /// </summary>
        public string UserAgent => _UserAgent.Value;
        /// <inheritdoc/>
        public Task Ready => _Ready ??= InitAsync();
        private Task? _Ready = null;
        private BlazorJSRuntime JS;
        /// <summary>
        /// The global Crypto object<br/>
        /// </summary>
        public Crypto? Crypto { get; private set; }
        /// <summary>
        /// The SubtleCrypto object for performing cryptographic operations<br/>
        /// </summary>
        public SubtleCrypto? SubtleCrypto { get; private set; }
        /// <summary>
        /// The devices signing key pair<br/>
        /// </summary>
        public CryptoKeyPair? SigningKeys { get; set; }
        /// <summary>
        /// The devices public signing key<br/>
        /// </summary>
        public CryptoKey PublicSigningKey => SigningKeys!.PublicKey!;
        /// <summary>
        /// The devices asymmetric encryption key pair<br/>
        /// </summary>
        public CryptoKeyPair? EncryptionKeys { get; set; }
        /// <summary>
        /// The devices public encryption key<br/>
        /// </summary>
        public CryptoKey PublicEncryptionKey => EncryptionKeys!.PublicKey!;
        /// <summary>
        /// The CryptoKey store for storing keys<br/>
        /// </summary>
        public BrowserWASMCryptoKeyStore KeyStore { get; }
        /// <summary>
        /// This instance's randomly generated identifier<br/>
        /// Not guaranteed to be unique<br/>
        /// </summary>
        public string InstanceId { get; }
        /// <summary>
        /// This device's public signing key hash<br/>
        /// </summary>
        public string PublicSigningKeyHash { get; private set; }
        /// <summary>
        /// This device's public signing key in base64 format<br/>
        /// </summary>
        public string PublicSigningKeyBase64 { get; private set; }
        /// <summary>
        /// This device's public signing key in hex format<br/>
        /// </summary>
        public string PublicSigningKeyHex { get; private set; }
        /// <summary>
        /// This device's public signing key as a byte array<br/>
        /// </summary>
        public byte[] PublicSigningKeyBytes { get; private set; }
        /// <summary>
        /// This device's public encryption key hash<br/>
        /// </summary>
        public string PublicEncryptionKeyHash { get; private set; }
        /// <summary>
        /// This device's public encryption key in base64 format<br/>
        /// </summary>
        public string PublicEncryptionKeyBase64 { get; private set; }
        /// <summary>
        /// This device's public encryption key in hex format<br/>
        /// </summary>
        public string PublicEncryptionKeyHex { get; private set; }
        /// <summary>
        /// This device's public encryption key as a byte array<br/>
        /// </summary>
        public byte[] PublicEncryptionKeyBytes { get; private set; }
        /// <summary>
        /// Creates a new DeviceIdentityService instance<br/>
        /// </summary>
        /// <param name="js"></param>
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
        public DeviceIdentityService(BlazorJSRuntime js)
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
        {
            JS = js;
            _UserAgent = new Lazy<string>(() => JS.Get<string>("navigator.userAgent"));
            InstanceId = JS.InstanceId;
            KeyStore = new BrowserWASMCryptoKeyStore(nameof(DeviceIdentityService));
        }
        private async Task InitAsync()
        {
            if (!Crypto.IsSupported) return;
            Crypto = new Crypto();
            SubtleCrypto = Crypto.Subtle;
            Cache = await Cache.OpenCache(nameof(DeviceIdentityService));
            await InitKeys();
        }
        private async Task InitKeys()
        {
            // try to load signing keys
            SigningKeys = await KeyStore.Get(nameof(SigningKeys));
            // create new keys if needed
            if (SigningKeys == null)
            {
                SigningKeys = await GenerateECDSASigningKey();
                await KeyStore.Set(nameof(SigningKeys), SigningKeys);
            }
            PublicSigningKeyBytes = await PublicKeyToBytes(SigningKeys!.PublicKey!);
            PublicSigningKeyHash = await PublicKeyToHash(SigningKeys!.PublicKey!);
            PublicSigningKeyBase64 = ToBase64String(PublicSigningKeyBytes); ;
            PublicSigningKeyHex = ToHexString(PublicSigningKeyBytes);
            // try to load asymmetric encryption keys
            EncryptionKeys = await KeyStore.Get(nameof(EncryptionKeys));
            // create new keys if needed
            if (EncryptionKeys == null)
            {
                EncryptionKeys = await GenerateECDHEncryptionKey();
                await KeyStore.Set(nameof(EncryptionKeys), EncryptionKeys);
            }
            PublicEncryptionKeyBytes = await PublicKeyToBytes(EncryptionKeys!.PublicKey!);
            PublicEncryptionKeyHash = await PublicKeyToHash(EncryptionKeys!.PublicKey!);
            PublicEncryptionKeyBase64 = ToBase64String(PublicEncryptionKeyBytes);
            PublicEncryptionKeyHex = ToHexString(PublicEncryptionKeyBytes);
            // log keys
            Console.WriteLine($"PublicSigningKeyHash: {PublicSigningKeyHash}");
            Console.WriteLine($"PublicEncryptionKeyHash: {PublicEncryptionKeyHash}");
            Console.WriteLine($"PublicSigningKeyBase64: {PublicSigningKeyBase64}");
            Console.WriteLine($"PublicEncryptionKeyBase64: {PublicEncryptionKeyBase64}");
            Console.WriteLine($"PublicSigningKeyHex: {PublicSigningKeyHex}");
            Console.WriteLine($"PublicEncryptionKeyHex: {PublicEncryptionKeyHex}");
            // device name
            var deviceName = await Cache.ReadText("deviceName");
            if (string.IsNullOrEmpty(deviceName))
            {
                deviceName = PublicSigningKeyHash;
                await Cache.WriteText("deviceName", deviceName);
            }
            // identity
            Identity = new DeviceIdentity
            {
                DeviceName = deviceName,
                UserAgent = UserAgent,
                InstanceId = InstanceId,
                Encrypt = PublicEncryptionKeyHex,
                Sign = PublicSigningKeyHex,
                SignHash = PublicSigningKeyHash,
                EncryptHash = PublicEncryptionKeyHash,
            };
            JS.Log("Identity", Identity);
            //var data = new byte[] { 1, 2, 3 };
            //var sig = await Sign(data);
            //var verified = await Verify(data, sig);
            //var otherKeyPair = await GenerateECDHEncryptionKey();
            //var aesKey = await DeriveAesGcmEncryptionKey(otherKeyPair.PublicKey);
            //var iv = GenerateAesGcmIVBytes();
            //var cipherData = await EncryptAesGcm(aesKey, data, iv);
            //var dataBack = await DecryptAesGcm(aesKey, cipherData, iv);
            //var dataRB = (byte[])dataBack!;//.ReadBytes();
            //var nmt = true;
        }
        /// <summary>
        /// Fires when the identity is updated
        /// </summary>
        public event Action OnIdentityUpdated = default!;
        /// <summary>
        /// Sets the device name
        /// </summary>
        /// <param name="deviceName"></param>
        /// <returns></returns>
        public async Task SetDeviceName(string deviceName)
        {
            await Cache.WriteText("deviceName", deviceName);
            Identity.DeviceName = deviceName;
            OnIdentityUpdated?.Invoke();
        }
        /// <summary>
        /// Checks if the provided public key matches the provided public key hash
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="publicKeyHash"></param>
        /// <returns></returns>
        public async Task<bool> ValidatePublicKeyHash(CryptoKey publicKey, string publicKeyHash)
        {
            return publicKeyHash == await PublicKeyToHash(publicKey);
        }
        /// <summary>
        /// Creates a simple hash from an EC public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public async Task<string> PublicKeyToHash(CryptoKey publicKey)
        {
            var spkiBytes = await PublicKeyToBytes(publicKey);
            return spkiBytes.SimpleCrc(8).ToHexString();
        }
        /// <summary>
        /// Creates a hex string from an EC public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public async Task<string> PublicKeyToHex(CryptoKey publicKey)
        {
            using var publicKeySpki = await SubtleCrypto!.ExportKeySpki(publicKey);
            var publicKeyHash = ToHexString(publicKeySpki.ReadBytes());
            return publicKeyHash;
        }
        /// <summary>
        /// Exports a private key to a pkcs8 formatted hex string.
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public async Task<string> PrivateKeyToHex(CryptoKey privateKey)
        {
            using var pkcs8ArrayBuffer = await SubtleCrypto!.ExportKeyPkcs8(privateKey);
            var keyHex = ToHexString(pkcs8ArrayBuffer.ReadBytes());
            return keyHex;
        }
        /// <summary>
        /// Exports a private key to a pkcs8 formatted byte array.
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public async Task<byte[]> PrivateKeyToBytes(CryptoKey privateKey)
        {
            using var pkcs8ArrayBuffer = await SubtleCrypto!.ExportKeyPkcs8(privateKey);
            return pkcs8ArrayBuffer.ReadBytes();
        }
        /// <summary>
        /// Exports a private key to a pkcs8 formatted base 64 string.
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public async Task<string> PrivateKeyToBase64(CryptoKey privateKey)
        {
            using var pkcs8ArrayBuffer = await SubtleCrypto!.ExportKeyPkcs8(privateKey);
            var bytes = pkcs8ArrayBuffer.ReadBytes();
            return ToBase64String(bytes);
        }
        /// <summary>
        /// Exports a private key to a pkcs8 formatted ArrayBuffer
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public async Task<ArrayBuffer> PrivateKeyToArrayBuffer(CryptoKey privateKey)
        {
            using var pkcs8ArrayBuffer = await SubtleCrypto!.ExportKeyPkcs8(privateKey);
            return pkcs8ArrayBuffer;
        }
        /// <summary>
        /// Creates a CryptoKeyPair from a pkcs8 formatted EC private key byte array
        /// </summary>
        /// <param name="privateKeyPkcs8"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public async Task<CryptoKeyPair> PrivateKeyECDHFrom(string privateKeyPkcs8, bool extractable = true)
        {
            if (HexPattern.IsMatch(privateKeyPkcs8))
            {
                return await PrivateKeyECDHFromHex(privateKeyPkcs8, extractable);
            }
            else
            {
                return await PrivateKeyECDHFromBase64(privateKeyPkcs8, extractable);
            }
        }
        /// <summary>
        /// Creates a CryptoKeyPair from a pkcs8 formatted EC private key hex string
        /// </summary>
        /// <param name="privateKeyPkcs8"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public async Task<CryptoKeyPair> PrivateKeyECDHFromHex(string privateKeyPkcs8, bool extractable = true)
        {
            byte[] bytes = FromHexString(privateKeyPkcs8);
            return await PrivateKeyECDHFrom(bytes, extractable);
        }
        /// <summary>
        /// Creates a CryptoKeyPair from a pkcs8 formatted EC private key base 64 string
        /// </summary>
        /// <param name="privateKeyPkcs8"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public async Task<CryptoKeyPair> PrivateKeyECDHFromBase64(string privateKeyPkcs8, bool extractable = true)
        {
            byte[] bytes = FromBase64String(privateKeyPkcs8);
            return await PrivateKeyECDHFrom(bytes, extractable);
        }
        /// <summary>
        /// Creates an ECDH CryptoKeyPair from a pkcs8 private key byte array<br/>
        /// </summary>
        /// <param name="privateKeyPkcs8"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<CryptoKeyPair> PrivateKeyECDHFrom(byte[] privateKeyPkcs8, bool extractable = true)
        {
            var namedCurve = Pkcs8Parser.GetECNamedCurve(privateKeyPkcs8);
            if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Invalid key");
            var keyUsages = new string[] { "deriveBits", "deriveKey" };
            var privateKey = await SubtleCrypto!.ImportKey<CryptoKey>("pkcs8", privateKeyPkcs8, new EcKeyImportParams { Name = "ECDH", NamedCurve = namedCurve }, extractable, keyUsages);
            if (extractable)
            {
                // export the private key as ECJWKPublic drops the D property which changes it to an exported public key
                var jwk = await SubtleCrypto.ExportKey<ECJWKPublic>("jwk", privateKey);
                var publicKey = await SubtleCrypto.ImportKey(jwk, new EcKeyImportParams { Name = "ECDH", NamedCurve = namedCurve }, extractable, new string[] { });
                var key = new CryptoKeyPair
                {
                    PublicKey = publicKey,
                    PrivateKey = privateKey,
                };
                return key;
            }
            else
            {
                // export the private key as ECJWKPublic drops the D property which changes it to an exported public key
                using var extractablePrivateKey = await SubtleCrypto!.ImportKey<CryptoKey>("pkcs8", privateKeyPkcs8, new EcKeyImportParams { Name = "ECDH", NamedCurve = namedCurve }, true, keyUsages);
                var jwk = await SubtleCrypto.ExportKey<ECJWKPublic>("jwk", extractablePrivateKey);
                var publicKey = await SubtleCrypto.ImportKey(jwk, new EcKeyImportParams { Name = "ECDH", NamedCurve = namedCurve }, extractable, new string[] { });
                var key = new CryptoKeyPair
                {
                    PublicKey = publicKey,
                    PrivateKey = privateKey,
                };
                return key;
            }
        }
        /// <summary>
        /// Creates a byte array from an EC public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public async Task<byte[]> PublicKeyToBytes(CryptoKey publicKey)
        {
            using var publicKeySpki = await SubtleCrypto!.ExportKeySpki(publicKey);
            var bytes = publicKeySpki.ReadBytes();
            return bytes;
        }
        /// <summary>
        /// Creates an ArrayBuffer from an EC public key<br/>
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public async Task<ArrayBuffer> PublicKeyToArrayBuffer(CryptoKey publicKey)
        {
            var publicKeySpki = await SubtleCrypto!.ExportKeySpki(publicKey);
            return publicKeySpki;
        }
        /// <summary>
        /// Creates a base64 string from an EC public key<br/>
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public async Task<string> PublicKeyToBase64(CryptoKey publicKey)
        {
            using var publicKeySpki = await SubtleCrypto!.ExportKeySpki(publicKey);
            var bytes = publicKeySpki.ReadBytes();
            var publicKeyBase64 = ToBase64String(bytes);
            return publicKeyBase64;
        }
        /// <summary>
        /// Creates a base64 url safe string from a byte array<br/>
        /// </summary>
        /// <param name="toEncodeAsBytes"></param>
        /// <returns></returns>
        public string ToBase64UrlSafe(byte[] toEncodeAsBytes) => Convert.ToBase64String(toEncodeAsBytes).TrimEnd(padding).Replace('+', '-').Replace('/', '_');
        /// <summary>
        /// Creates a byte array from a base64 url safe string<br/>
        /// </summary>
        /// <param name="base64UrlSafe"></param>
        /// <returns></returns>
        public byte[] FromBase64UrlSafe(string base64UrlSafe)
        {
            string incoming = base64UrlSafe.Replace('_', '/').Replace('-', '+');
            switch (base64UrlSafe.Length % 4)
            {
                case 2: incoming += "=="; break;
                case 3: incoming += "="; break;
            }
            return Convert.FromBase64String(incoming);
        }
        /// <summary>
        /// Default JsonSerializerOptions used for signing and verifying objects<br/>
        /// </summary>
        public JsonSerializerOptions JsonSerializerOptions { get; protected set; } = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        /// <summary>
        /// Creates an ECDH public CryptoKey from an spki string in either hex or base64 format<br/>
        /// </summary>
        /// <param name="spki"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public async Task<CryptoKey> PublicKeyECDHFrom(string spki, bool extractable = true)
        {
            if (HexPattern.IsMatch(spki))
            {
                return await PublicKeyECDHFromHex(spki, extractable);
            }
            else
            {
                return await PublicKeyECDHFromBase64(spki, extractable);
            }
        }
        /// <summary>
        /// Creates an ECDSA public CryptoKey from an spki string in either hex or base64 format<br/>
        /// </summary>
        /// <param name="spki"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public async Task<CryptoKey> PublicKeyECDSAFrom(string spki, bool extractable = true)
        {
            if (HexPattern.IsMatch(spki))
            {
                return await PublicKeyECDSAFromHex(spki, extractable);
            }
            else
            {
                return await PublicKeyECDSAFromBase64(spki, extractable);
            }
        }
        /// <summary>
        /// Creates an ECDH public CryptoKey from an spki byte array<br/>
        /// </summary>
        /// <param name="spki"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<CryptoKey> PublicKeyECDHFrom(byte[] spki, bool extractable = true)
        {
            var namedCurve = SpkiParser.GetECNamedCurve(spki);
            if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Invalid key");
            return await SubtleCrypto!.ImportKey("spki", spki, new EcKeyImportParams { Name = "ECDH", NamedCurve = namedCurve }, extractable, new string[] { });
        }
        /// <summary>
        /// Creates an ECDSA public CryptoKey from an spki byte array<br/>
        /// </summary>
        /// <param name="spki"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<CryptoKey> PublicKeyECDSAFrom(byte[] spki, bool extractable = true)
        {
            var namedCurve = SpkiParser.GetECNamedCurve(spki);
            if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Invalid key");
            return await SubtleCrypto!.ImportKey("spki", spki, new EcKeyImportParams { Name = "ECDSA", NamedCurve = namedCurve }, extractable, new string[] { "verify" });
        }
        /// <summary>
        /// Creates an ECDH public CryptoKey from an spki hex formatted string<br/>
        /// </summary>
        /// <param name="spkiHex"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<CryptoKey> PublicKeyECDHFromHex(string spkiHex, bool extractable = true)
        {
            var publicKeyBytes = FromHexString(spkiHex);
            var namedCurve = SpkiParser.GetECNamedCurve(publicKeyBytes);
            if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Invalid key");
            return await SubtleCrypto!.ImportKey("spki", publicKeyBytes, new EcKeyImportParams { Name = "ECDH", NamedCurve = namedCurve }, extractable, new string[] { });
        }
        /// <summary>
        /// Creates an ECDH public CryptoKey from an spki base64 formatted string<br/>
        /// </summary>
        /// <param name="spkiBase64"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<CryptoKey> PublicKeyECDHFromBase64(string spkiBase64, bool extractable = true)
        {
            var publicKeyBytes = FromBase64String(spkiBase64);
            var namedCurve = SpkiParser.GetECNamedCurve(publicKeyBytes);
            if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Invalid key");
            return await SubtleCrypto!.ImportKey("spki", publicKeyBytes, new EcKeyImportParams { Name = "ECDH", NamedCurve = namedCurve }, extractable, new string[] { });
        }
        /// <summary>
        /// Creates an ECDSA public CryptoKey from an spki hex formatted string<br/>
        /// </summary>
        /// <param name="spkiHex"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<CryptoKey> PublicKeyECDSAFromHex(string spkiHex, bool extractable = true)
        {
            var publicKeyBytes = FromHexString(spkiHex);
            var namedCurve = SpkiParser.GetECNamedCurve(publicKeyBytes);
            if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Invalid key");
            return await SubtleCrypto!.ImportKey("spki", publicKeyBytes, new EcKeyImportParams { Name = "ECDSA", NamedCurve = namedCurve }, extractable, new[] { "verify" });
        }
        /// <summary>
        /// Creates an ECDSA public CryptoKey from an spki base64 formatted string<br/>
        /// </summary>
        /// <param name="spkiBase64"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<CryptoKey> PublicKeyECDSAFromBase64(string spkiBase64, bool extractable = true)
        {
            var publicKeyBytes = FromBase64String(spkiBase64);
            var namedCurve = SpkiParser.GetECNamedCurve(publicKeyBytes);
            if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Invalid key");
            return await SubtleCrypto!.ImportKey("spki", publicKeyBytes, new EcKeyImportParams { Name = "ECDSA", NamedCurve = namedCurve }, extractable, new[] { "verify" });
        }
        /// <summary>
        /// Creates a signature on the provided object using the stored private key<br/>
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="obj"></param>
        /// <param name="expirationUtc"></param>
        /// <returns></returns>
        public Task Sign<T>(T obj, DateTime? expirationUtc = null) where T : SignedObject => Sign(SigningKeys!.PrivateKey!, obj, expirationUtc);
        /// <summary>
        /// Creates a signature on the provided object using the stored private key<br/>
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="obj"></param>
        /// <param name="expireFromNow"></param>
        /// <returns></returns>
        public Task Sign<T>(T obj, TimeSpan expireFromNow) where T : SignedObject => Sign(SigningKeys!.PrivateKey!, obj, expireFromNow);
        /// <summary>
        /// Creates a signature on the provided object using the provided private key<br/>
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="privateKey"></param>
        /// <param name="obj"></param>
        /// <param name="expireFromNow"></param>
        /// <returns></returns>
        public Task Sign<T>(CryptoKey privateKey, T obj, TimeSpan expireFromNow) where T : SignedObject
            => Sign(privateKey, obj, DateTime.Now + expireFromNow);
        /// <summary>
        /// Creates a signature on the provided object using the provided private key<br/>
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="privateKey"></param>
        /// <param name="obj"></param>
        /// <param name="expirationUtc"></param>
        /// <returns></returns>
        public async Task Sign<T>(CryptoKey privateKey, T obj, DateTime? expirationUtc = null) where T : SignedObject
        {
            var signature = new Signature
            {
                Alg = privateKey.AlgorithmName,
                PublicKey = PublicSigningKeyHex,
                TokenSigned = DateTime.Now,
                TokenExpiration = expirationUtc,
            };
            obj.Signatures.Add(signature);
            // serialize in current state
            var data = JsonSerializer.SerializeToUtf8Bytes(obj, JsonSerializerOptions);
            var sig = await SignBase64(privateKey, data);
            signature.Token = sig;
        }
        /// <summary>
        /// Returns a fingerprint of a public hex string
        /// </summary>
        /// <param name="hex"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public string GetSignerHexKeyFingerprint(string hex, int length = 8)
        {
            var bytes = Convert.FromHexString(hex);
            var fingerprintBytes = bytes.SimpleCrc(length);
            return ToHexString(fingerprintBytes);
        }
        /// <summary>
        /// Returns a fingerprint of a public hex string
        /// </summary>
        /// <param name="hex"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public byte[] GetSignerHexKeyFingerprintBytes(string hex, int length = 8)
        {
            var bytes = Convert.FromHexString(hex);
            var fingerprintBytes = bytes.SimpleCrc(length);
            return fingerprintBytes;
        }
        /// <summary>
        /// Creates a signature using the provided private key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public async Task<string> SignBase64(CryptoKey privateKey, Union<ArrayBuffer, TypedArray, DataView, byte[]> data)
        {
            var bytes = await SignBytes(privateKey, data);
            return ToBase64String(bytes);
        }
        /// <summary>
        /// Creates a signature using the provided private key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public async Task<byte[]> SignBytes(CryptoKey privateKey, Union<ArrayBuffer, TypedArray, DataView, byte[]> data)
        {
            using var arrayBufferSig = await Sign(privateKey, data);
            return arrayBufferSig.ReadBytes();
        }
        /// <summary>
        /// Creates a signature using the provided private key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<ArrayBuffer> Sign(CryptoKey privateKey, Union<ArrayBuffer, TypedArray, DataView, byte[]> data)
        {
            switch (privateKey.AlgorithmName)
            {
                case "ECDSA":
                    return await SubtleCrypto!.Sign(DefaultEcdsaParams, privateKey, data);
                default:
                    throw new Exception("Invalid keys");
            }
        }
        /// <summary>
        /// Creates a signature using the stored private key
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public Task<ArrayBuffer> Sign(Union<ArrayBuffer, TypedArray, DataView, byte[]> data) => Sign(SigningKeys!.PrivateKey!, data);
        /// <summary>
        /// Verifies that all signatures on an object are valid<br/>
        /// Does not check who signed it, only that the signatures are valid<br/>
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="signedObject"></param>
        /// <param name="verifyTimestampIfExpirable"></param>
        /// <returns></returns>
        public async Task<bool> Verify<T>(T signedObject, bool verifyTimestampIfExpirable = true) where T : SignedObject
        {
            if (signedObject == null) return false;
            var sigs = signedObject.Signatures.ToList();
            signedObject.Signatures.Clear();
            foreach (var sig in sigs)
            {
                if (verifyTimestampIfExpirable && sig.TokenExpiration != null)
                {
                    var now = DateTime.Now;
                    if (now > sig.TokenExpiration)
                    {
                        return false;
                    }
                }
                using var signerKey = await PublicKeyECDSAFromHex(sig.PublicKey);
                var tokenToVerify = sig.Token;
                sig.Token = "";
                signedObject.Signatures.Add(sig);
                // verify the token
                var serializedData = JsonSerializer.SerializeToUtf8Bytes(signedObject, JsonSerializerOptions);
                var verified1 = await Verify(signerKey, serializedData, tokenToVerify);
                if (!verified1) return false;
                sig.Token = tokenToVerify;
            }
            return true;
        }
        /// <summary>
        /// Verifies a signature using the stored public key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public Task<bool> Verify(Union<ArrayBuffer, TypedArray, DataView, byte[]> data, ArrayBuffer signature) => Verify(SigningKeys!.PublicKey!, data, signature);
        /// <summary>
        /// Verifies a signature using the provided public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="data"></param>
        /// <param name="base64Signature"></param>
        /// <returns></returns>
        public async Task<bool> Verify(CryptoKey publicKey, Union<ArrayBuffer, TypedArray, DataView, byte[]> data, string base64Signature)
        {
            var bytes = FromBase64String(base64Signature);
            return await Verify(publicKey, data, bytes);
        }
        /// <summary>
        /// Verifies a signature using the provided public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public async Task<bool> Verify(CryptoKey publicKey, Union<ArrayBuffer, TypedArray, DataView, byte[]> data, byte[] signature)
        {
            using var sig = (ArrayBuffer)signature!;
            return await Verify(publicKey, data, sig);
        }
        /// <summary>
        /// Verifies a signature using the provided public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<bool> Verify(CryptoKey publicKey, Union<ArrayBuffer, TypedArray, DataView, byte[]> data, ArrayBuffer signature)
        {
            switch (publicKey.AlgorithmName)
            {
                case "ECDSA":
                    return await SubtleCrypto!.Verify(DefaultEcdsaParams, publicKey, signature, data);
                default:
                    throw new Exception("Invalid keys");
            }
        }
        /// <summary>
        /// Returns a derived crypto key or throws an exception if it fails
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        /// <exception cref="NullReferenceException"></exception>
        public async Task<CryptoKey> DeriveAesGcmEncryptionKey(CryptoKey? publicKey)
        {
            if (publicKey == null || EncryptionKeys == null || EncryptionKeys.PrivateKey == null)
            {
                throw new NullReferenceException("CryptoKey must be set");
            }
            return await SubtleCrypto!.DeriveKey(new EcdhKeyDeriveParams { Public = publicKey }, EncryptionKeys.PrivateKey, new AesKeyGenParams { Name = "AES-GCM", Length = 256 }, false, new string[] { "encrypt", "decrypt" });
        }
        /// <summary>
        /// Generates a shared encryption key from this user's privateKey and the other user's publicKey<br/>
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public Task<CryptoKey> DeriveAesGcmEncryptionKey(CryptoKey privateKey, CryptoKey publicKey)
        {
            return SubtleCrypto!.DeriveKey(new EcdhKeyDeriveParams { Public = publicKey }, privateKey, new AesKeyGenParams { Name = "AES-GCM", Length = 256 }, false, new string[] { "encrypt", "decrypt" });
        }
        /// <summary>
        /// Generates an IV for use in AesGcmEncryption
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
        public Uint8Array GenerateAesGcmIV(int size = 12)
        {
            using var iv = new Uint8Array(size);
            return Crypto!.GetRandomValues(iv);
        }
        /// <summary>
        /// Generates an IV for use in AesGcmEncryption
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
        public byte[] GenerateAesGcmIVBytes(int size = 12)
        {
            return Crypto!.GetRandomValues(size);
        }
        /// <summary>
        /// Encrypts it using AES in GCM mode.
        /// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#aes-gcm_2
        /// </summary>
        /// <returns></returns>
        public async Task<ArrayBuffer> EncryptAesGcm(CryptoKey aesGcmKey, Union<ArrayBuffer, TypedArray, DataView, byte[]> data, Union<ArrayBuffer, TypedArray, DataView, byte[]> iv)
        {
            var ret = await SubtleCrypto!.Encrypt(new AesGcmParams { Iv = iv }, aesGcmKey, data);
            return ret;
        }
        /// <summary>
        /// This method generates the iv internally and uses MessagePack to put the encrypted data and the iv into a single byte array<br/>
        /// </summary>
        /// <param name="aesGcmKey"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public async Task<byte[]> EncryptAesGcmIVBytes(CryptoKey aesGcmKey, Union<ArrayBuffer, TypedArray, DataView, byte[]> data)
        {
            using var uint8array = await EncryptAesGcmIV(aesGcmKey, data);
            return uint8array.ReadBytes();
        }
        /// <summary>
        /// This method generates the iv internally and uses MessagePack to put the encrypted data and the iv into a single Uint8Array<br/>
        /// </summary>
        /// <param name="aesGcmKey"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public async Task<Uint8Array> EncryptAesGcmIV(CryptoKey aesGcmKey, Union<ArrayBuffer, TypedArray, DataView, byte[]> data)
        {
            using var iv = GenerateAesGcmIV();
            using var cypher = await SubtleCrypto!.Encrypt(new AesGcmParams { Iv = iv }, aesGcmKey, data);
            // MessagePAck does not work with ArrayBuffers so convert to Uint8Array
            using var cypherUint8Array = new Uint8Array(cypher);
            var ret = MessagePackSerializer.Encode(new object[] { iv, cypherUint8Array });
            return ret;
        }
        /// <summary>
        /// Decrypts it using AES in GCM mode.
        /// </summary>
        /// <param name="aesGcmKey"></param>
        /// <param name="cipherData"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public async Task<ArrayBuffer> DecryptAesGcm(CryptoKey aesGcmKey, Union<ArrayBuffer, TypedArray, DataView, byte[]> cipherData, Union<ArrayBuffer, TypedArray, DataView, byte[]> iv)
        {
            var ret = await SubtleCrypto!.Decrypt(new AesGcmParams { Iv = iv }, aesGcmKey, cipherData);
            return ret;
        }
        /// <summary>
        /// Decrypts a cypher that has been packed with the generated iv using MessagePack
        /// </summary>
        /// <param name="aesGcmKey"></param>
        /// <param name="cipherDataWithIV"></param>
        /// <returns></returns>
        public async Task<ArrayBuffer> DecryptAesGcmIV(CryptoKey aesGcmKey, Uint8Array cipherDataWithIV)
        {
            var (iv, cipherData) = MessagePackSerializer.Decode<(Uint8Array, Uint8Array)>(cipherDataWithIV);
            var ret = await SubtleCrypto!.Decrypt(new AesGcmParams { Iv = iv }, aesGcmKey, cipherData);
            return ret;
        }
        /// <summary>
        /// Generates a new ECDH key pair that can be used to derive a shared AES encryption key.<br/>
        /// If not extractable, the private key cannot be exported.<br/>
        /// To reuse the key pair, store it in the CryptoKeyStore.<br/>
        /// </summary>
        /// <returns></returns>
        public async Task<CryptoKeyPair> GenerateECDHEncryptionKey(bool extractable = false)
        {
            var keys = await SubtleCrypto!.GenerateKey<CryptoKeyPair>(new EcKeyGenParams
            {
                Name = "ECDH",
                NamedCurve = ECDHNamedCurve
            }, extractable, new string[] { "deriveKey" });
            return keys;
        }
        /// <summary>
        /// Generates an ECDSA signing key pair.<br/>
        /// If not extractable, the private key cannot be exported.<br/>
        /// To reuse the key pair, store it in the CryptoKeyStore.<br/>
        /// </summary>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public async Task<CryptoKeyPair> GenerateECDSASigningKey(bool extractable = false)
        {
            var keys = await SubtleCrypto!.GenerateKey<CryptoKeyPair>(new EcKeyGenParams
            {
                Name = "ECDSA",
                NamedCurve = ECDSANamedCurve
            }, extractable, new string[] { "sign", "verify" });
            return keys;
        }
        string ToBase64String(byte[] bytes, bool safe = true) => safe ? ToBase64UrlSafe(bytes) : Convert.ToBase64String(bytes);
        byte[] FromBase64String(string base64Url) => FromBase64UrlSafe(base64Url);
        string ToHexString(byte[] bytes, bool toLower = true) => bytes.ToHexString(toLower);
        byte[] FromHexString(string value) => Convert.FromHexString(value);
        static Regex HexPattern = new Regex("^[0-9a-fA-F]+$", RegexOptions.Compiled);
        static readonly char[] padding = { '=' };
        //public string DeflateStringToBase64UrlSafe(string data, CompressionLevel compressionLevel = CompressionLevel.Optimal)
        //{
        //    var bytes = Encoding.UTF8.GetBytes(data);
        //    using (var memoryStream = new MemoryStream())
        //    {
        //        using (var gzipStream = new GZipStream(memoryStream, compressionLevel))
        //        {
        //            gzipStream.Write(bytes, 0, bytes.Length);
        //        }
        //        var deflatedBytes = memoryStream.ToArray();
        //        return ToBase64UrlSafe(deflatedBytes);
        //    }
        //}
        //public string InflateStringFromBase64UrlSafe(string deflatedBase64)
        //{
        //    byte[] bytes = FromBase64UrlSafe(deflatedBase64);
        //    using (var memoryStream = new MemoryStream(bytes))
        //    {
        //        using (var outputStream = new MemoryStream())
        //        {
        //            using (var decompressStream = new GZipStream(memoryStream, CompressionMode.Decompress))
        //            {
        //                decompressStream.CopyTo(outputStream);
        //            }
        //            var inflatedBytes = outputStream.ToArray();
        //            return Encoding.UTF8.GetString(inflatedBytes);
        //        }
        //    }
        //}
        //public byte[] GZip(byte[] bytes, CompressionLevel compressionLevel = CompressionLevel.Optimal)
        //{
        //    using (var memoryStream = new MemoryStream())
        //    {
        //        using (var gzipStream = new GZipStream(memoryStream, compressionLevel))
        //        {
        //            gzipStream.Write(bytes, 0, bytes.Length);
        //        }
        //        return memoryStream.ToArray();
        //    }
        //}
        //public byte[] GUnzip(byte[] bytes)
        //{
        //    using (var memoryStream = new MemoryStream(bytes))
        //    {
        //        using (var outputStream = new MemoryStream())
        //        {
        //            using (var decompressStream = new GZipStream(memoryStream, CompressionMode.Decompress))
        //            {
        //                decompressStream.CopyTo(outputStream);
        //            }
        //            return outputStream.ToArray();
        //        }
        //    }
        //}
        //public byte[] Zip(byte[] textToZip)
        //{
        //    using (var memoryStream = new MemoryStream())
        //    {
        //        using (var zipArchive = new ZipArchive(memoryStream, ZipArchiveMode.Create, true))
        //        {
        //            var demoFile = zipArchive.CreateEntry("a");
        //            using (var entryStream = demoFile.Open())
        //            {
        //                using (var streamWriter = new BinaryWriter(entryStream))
        //                {
        //                    streamWriter.Write(textToZip);
        //                }
        //            }
        //        }
        //        memoryStream.Position = 0;
        //        return memoryStream.ToArray();
        //    }
        //}
        //public byte[]? Unzip(byte[] zippedBuffer)
        //{
        //    using (var zippedStream = new MemoryStream(zippedBuffer))
        //    {
        //        using (var archive = new ZipArchive(zippedStream))
        //        {
        //            var entry = archive.Entries.FirstOrDefault();
        //            if (entry != null)
        //            {
        //                using (var unzippedEntryStream = entry.Open())
        //                {
        //                    using (var ms = new MemoryStream())
        //                    {
        //                        unzippedEntryStream.CopyTo(ms);
        //                        var ret = ms.ToArray();
        //                        return ret;
        //                    }
        //                }
        //            }
        //            return null;
        //        }
        //    }
        //}
    }
}

