public static class Pkcs8Parser
{
    // --- OID Definitions for Named Curves ---
    // These are the byte sequences for the OIDs as they appear in the DER encoding.
    // The format is a dictionary of OID bytes mapped to the curve name.
    private static readonly Dictionary<byte[], string> NamedCurveOids = new Dictionary<byte[], string>(new ByteArrayComparer())
    {
        // NIST P-256 (secp256r1): 1.2.840.10045.3.1.7
        { new byte[] { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 }, "P-256" }, 
        // NIST P-384 (secp384r1): 1.3.132.0.34
        { new byte[] { 0x2B, 0x81, 0x04, 0x00, 0x22 }, "P-384" },
        // NIST P-521 (secp521r1): 1.3.132.0.35
        { new byte[] { 0x2B, 0x81, 0x04, 0x00, 0x23 }, "P-521" },
    };

    // Helper class for byte array comparison in the Dictionary
    private class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public bool Equals(byte[] x, byte[] y)
        {
            if (x == null || y == null) return x == y;
            return x.SequenceEqual(y);
        }

        public int GetHashCode(byte[] obj)
        {
            if (obj == null) return 0;
            return obj.Sum(b => b); // Simple, non-collision-proof hash, but functional for this example
        }
    }

    /// <summary>
    /// Simple parser to extract the named curve OID from an unencrypted PKCS#8 byte array.
    /// WARNING: This is a fragile, non-robust ASN.1 parser.
    /// </summary>
    /// <param name="pkcs8Bytes">The DER-encoded PKCS#8 private key.</param>
    /// <returns>The identified named curve name or an error message.</returns>
    public static string? GetECNamedCurve(byte[] pkcs8Bytes)
    {
        if (pkcs8Bytes == null) return null;
        try
        {
            int offset = 0;

            // 1. Read the initial SEQUENCE tag (0x30)
            if (pkcs8Bytes[offset] != 0x30) return null;
            offset++;

            // 2. Read the length of the SEQUENCE
            // We skip the length reading as it's complex for all cases (single-byte vs. multi-byte length)
            // and is not strictly needed to find the OID. We jump over it.
            (int length, int bytesUsed) = ReadDerLength(pkcs8Bytes, offset);
            offset += bytesUsed;

            // 3. Read the Version INTEGER (0x02, length 0x01, value 0x00)
            // The structure should be: 0x02 0x01 0x00
            if (pkcs8Bytes.Length < offset + 3 ||
                pkcs8Bytes[offset] != 0x02 || pkcs8Bytes[offset + 1] != 0x01 || pkcs8Bytes[offset + 2] != 0x00)
                return null;
            offset += 3;

            // 4. Read the AlgorithmIdentifier SEQUENCE tag (0x30)
            if (pkcs8Bytes[offset] != 0x30)
                return null;
            offset++;

            // 5. Read the length of the AlgorithmIdentifier SEQUENCE
            (length, bytesUsed) = ReadDerLength(pkcs8Bytes, offset);
            offset += bytesUsed;

            // --- Inside AlgorithmIdentifier SEQUENCE ---

            // 6. Read the EC Public Key OID tag (0x06)
            if (pkcs8Bytes[offset] != 0x06)
                return null;
            offset++;

            // 7. Read the length of the EC Public Key OID
            (int primaryOidLength, bytesUsed) = ReadDerLength(pkcs8Bytes, offset);
            offset += bytesUsed;

            // 8. Skip the EC Public Key OID bytes (1.2.840.10045.2.1)
            // The EC Public Key OID is always 8 bytes: 0x2A 0x86 0x48 0xCE 0x3D 0x02 0x01 0x01
            offset += primaryOidLength;

            // 9. Read the Named Curve OID tag (0x06) - This is the PARAMETERS field
            if (pkcs8Bytes[offset] != 0x06)
                return null;
            offset++;

            // 10. Read the length of the Named Curve OID
            (int namedCurveOidLength, bytesUsed) = ReadDerLength(pkcs8Bytes, offset);
            offset += bytesUsed;

            // 11. Extract the Named Curve OID bytes
            if (pkcs8Bytes.Length < offset + namedCurveOidLength)
                return null;

            byte[] curveOidBytes = new byte[namedCurveOidLength];
            Array.Copy(pkcs8Bytes, offset, curveOidBytes, 0, namedCurveOidLength);

            // 12. Compare the extracted bytes with known OIDs
            if (NamedCurveOids.TryGetValue(curveOidBytes, out string curveName))
            {
                return curveName;
            }
        }
        catch (Exception ex)
        {
            var nmt = ex.ToString();
        }
        return null;
    }

    /// <summary>
    /// Rudimentary DER Length Reader (only supports short and 2-byte long form)
    /// </summary>
    private static (int length, int bytesUsed) ReadDerLength(byte[] data, int offset)
    {
        if (data[offset] < 0x80) // Short form (length < 128)
        {
            return (data[offset], 1);
        }
        else // Long form
        {
            int lengthBytes = data[offset] & 0x7F; // Number of following bytes for the length
            if (lengthBytes == 0 || lengthBytes > 2)
                throw new NotSupportedException("Only short and 2-byte long form length supported for this simple parser.");

            int length = 0;
            for (int i = 0; i < lengthBytes; i++)
            {
                length = (length << 8) | data[offset + 1 + i];
            }
            return (length, 1 + lengthBytes);
        }
    }
}