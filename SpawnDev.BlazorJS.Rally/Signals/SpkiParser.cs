/// <summary>
/// Extracts basic information from spki formatted public keys<br/>
/// </summary>
public static class SpkiParser
{
    private enum Asn1Type : byte
    {
        Sequence = 0x30,
        ObjectIdentifier = 0x06,
        BitString = 0x03
    }
    private static class EccOids
    {
        public static readonly byte[] EcPublicKey = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    }
    static Dictionary<string, byte[]> NamedCurves = new Dictionary<string, byte[]> {
        { "P-256", [ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 ] },
        { "P-384", [ 0x2B, 0x81, 0x04, 0x00, 0x22 ] },
        { "P-521", [ 0x2B, 0x81, 0x04, 0x00, 0x23 ] },
    };
    /// <summary>
    /// Returns the named curve for a supported EC (ECDSA or ECDH) public key in SPKI format, or null if not found.<br/>
    /// </summary>
    /// <param name="spkiBytes"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    public static string? GetECNamedCurve(byte[] spkiBytes)
    {
        if (spkiBytes == null) return null;
        try
        {
            var reader = new Asn1Reader(spkiBytes);
            // Expect a SEQUENCE
            var sequence = reader.ReadNext(Asn1Type.Sequence);
            // First item in SEQUENCE is another SEQUENCE (AlgorithmIdentifier)
            var algIdentifier = sequence.ReadNext(Asn1Type.Sequence);
            // First item of AlgorithmIdentifier is an OID (id-ecPublicKey)
            var algOid = algIdentifier.ReadNext(Asn1Type.ObjectIdentifier);
            if (!algOid.Value.SequenceEqual(EccOids.EcPublicKey))
            {
                // not an EC key
                return null;
            }
            // Second item of AlgorithmIdentifier is the curve OID
            var curveOid = algIdentifier.ReadNext(Asn1Type.ObjectIdentifier);
            foreach (var nckvp in NamedCurves)
            {
                if (curveOid.Value.SequenceEqual(nckvp.Value))
                {
                    return nckvp.Key;
                }
            }
        }
        catch { }
        return null;
    }

    private class Asn1Reader
    {
        private readonly byte[] _data;
        private int _position;
        public Asn1Reader(byte[] data)
        {
            _data = data;
        }
        public Asn1Node ReadNext(Asn1Type expectedType)
        {
            if (_position >= _data.Length)
            {
                throw new InvalidOperationException("End of data reached unexpectedly.");
            }
            // Read type and length
            var type = _data[_position++];
            if (type != (byte)expectedType)
            {
                throw new InvalidOperationException($"Expected type {expectedType}, but got {type:X2}.");
            }
            int length;
            if (_data[_position] < 0x80)
            {
                length = _data[_position];
                _position++;
            }
            else
            {
                var lengthBytes = _data[_position++] & 0x7F;
                if (lengthBytes > 4) throw new InvalidOperationException("Length too long.");

                length = 0;
                for (int i = 0; i < lengthBytes; i++)
                {
                    length = (length << 8) | _data[_position++];
                }
            }
            var valueBytes = new byte[length];
            Buffer.BlockCopy(_data, _position, valueBytes, 0, length);
            _position += length;
            return new Asn1Node(valueBytes);
        }
    }
    private class Asn1Node
    {
        private readonly byte[] _value;
        private readonly Asn1Reader _reader;
        public byte[] Value => _value;
        public Asn1Node(byte[] value)
        {
            _value = value;
            _reader = new Asn1Reader(value);
        }
        public Asn1Node ReadNext(Asn1Type expectedType)
        {
            return _reader.ReadNext(expectedType);
        }
    }
}
