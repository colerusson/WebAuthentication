using System.Text;

namespace App.Areas.Identity;

internal static class Utils
{

    /// <summary>
    /// Encoding used to convert strings to and from bytes.
    /// </summary>
    public static Encoding Encoding { get => Encoding.ASCII; }

    /// <summary>
    /// Encodes a salt and a digest into a string.
    /// </summary>
    /// <param name="salt">Salt to encode.</param>
    /// <param name="digest">Digest to encode.</param>
    /// <returns>Encoded salt and digest.</returns>
    public static string EncodeSaltAndDigest(byte[] salt, byte[] digest)
    {
        // todo: Encode as "Base64(salt):Base64(digest)"
        string encodedSalt = Convert.ToBase64String(salt);
        string encodedDigest = Convert.ToBase64String(digest);
        return $"{encodedSalt}:{encodedDigest}";
    }

    /// <summary>
    /// Decodes a salt and a digest from a string.
    /// </summary>
    /// <param name="salt">Salt to decode.</param>
    /// <param name="digest">Digest to decode.</param>
    /// <returns>Decoded salt and digest.</returns>
    public static (byte[], byte[]) DecodeSaltAndDigest(string value)
    {
        // todo: Decode as "Base64(salt):Base64(digest)"
        string[] parts = value.Split(':');
        if (parts.Length != 2) throw new ArgumentException("Invalid value");
        byte[] salt = Convert.FromBase64String(parts[0]);
        byte[] digest = Convert.FromBase64String(parts[1]);
        return (salt, digest);
    }
}
