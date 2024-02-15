using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by iterative SHA256 hashing.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class IterativeHasher : IPasswordHasher<IdentityUser>
{

    /// <summary>
    /// Hash a password using iterative SHA256 hashing.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password)
    {
        // todo: Use a random 32-byte salt. Use a 32-byte digest.
        // todo: Use 100,000 iterations and the SHA256 algorithm.
        // todo: Encode as "Base64(salt):Base64(digest)"
        byte[] salt = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        byte[] hashInput = new byte[salt.Length + Utils.Encoding.GetBytes(password).Length];
        salt.CopyTo(hashInput, 0);
        Utils.Encoding.GetBytes(password).CopyTo(hashInput, salt.Length);

        byte[] hash = SHA256.HashData(hashInput);
        for (int i = 0; i < 99999; i++)
        {
            hash = SHA256.HashData(hash);
        }

        return Utils.EncodeSaltAndDigest(salt, hash);
    }

    /// <summary>
    /// Verify that a password matches the hashed password.
    /// </summary>
    /// <param name="hashedPassword">Hashed password value stored when registering.</param>
    /// <param name="providedPassword">Password provided by user in login attempt.</param>
    /// <returns></returns>
    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword)
    {
        // todo: Verify that the given password matches the hashedPassword (as originally encoded by HashPassword)
        (byte[] salt, byte[] storedDigest) = Utils.DecodeSaltAndDigest(hashedPassword);

        byte[] hashInput = new byte[salt.Length + Utils.Encoding.GetBytes(providedPassword).Length];
        salt.CopyTo(hashInput, 0);
        Utils.Encoding.GetBytes(providedPassword).CopyTo(hashInput, salt.Length);

        byte[] providedDigest = SHA256.HashData(hashInput);
        for (int i = 0; i < 99999; i++)
        {
            providedDigest = SHA256.HashData(providedDigest);
        }

        if (Utils.EncodeSaltAndDigest(salt, providedDigest) == hashedPassword)
        {
            return PasswordVerificationResult.Success;
        }

        return PasswordVerificationResult.Failed;
    }

}