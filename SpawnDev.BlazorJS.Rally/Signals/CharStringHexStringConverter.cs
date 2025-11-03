using System.Text.Json;
using System.Text.Json.Serialization;


namespace SpawnDev.BlazorJS.Rally.Signals
{
    /// <summary>
    /// Handles conversion between character string and hexadecimal string or byte array representations during
    /// </summary>
    /// <remarks>This converter supports two types: <see cref="string"/> and <see cref="byte[]"/>.  During
    /// deserialization, it converts JSON string values into either a hexadecimal string or a byte array,  depending on
    /// the target type. During serialization, it converts a hexadecimal string or byte array  into a character string
    /// representation.</remarks>
    public class CharStringHexStringConverter : JsonConverter<object>
    {
        public override bool CanConvert(Type typeToConvert)
        {
            return typeToConvert == typeof(string) || typeToConvert == typeof(byte[]);
        }
        public override object Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var token = reader.TokenType;
            if (token == JsonTokenType.Null) return null;
            var byteString = reader.GetString();
            if (typeToConvert == typeof(string))
            {
                return byteString!.CharStringToHexString()!;
            }
            else if (typeToConvert == typeof(byte[]))
            {
                return byteString!.ToCharBytes();
            }
            return null!;
        }
        public override void Write(Utf8JsonWriter writer, object value, JsonSerializerOptions options)
        {
            if (value == null)
            {
                writer.WriteNullValue();
            }
            else if (value is string valueStr)
            {
                writer.WriteStringValue(valueStr.HexStringToCharString());
            }
            else if (value is byte[] valueBytes)
            {
                writer.WriteStringValue(valueBytes.ToCharString());
            }
        }
    }
}
