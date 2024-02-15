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
        byte[] digest = new byte[32];
        using (var sha = SHA256.Create())
        {
            byte[] input = Utils.Encoding.GetBytes(password);
            byte[] saltedInput = new byte[salt.Length + input.Length];
            salt.CopyTo(saltedInput, 0);
            input.CopyTo(saltedInput, salt.Length);
            byte[] hash = sha.ComputeHash(saltedInput);
            for (int i = 0; i < 99999; i++)
            {
                hash.CopyTo(saltedInput, 0);
                hash = sha.ComputeHash(saltedInput);
            }
            hash.CopyTo(digest, 0);
        }
        return Utils.EncodeSaltAndDigest(salt, digest);
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
        (byte[] salt, byte[] digest) = Utils.DecodeSaltAndDigest(hashedPassword);
        byte[] providedDigest = new byte[32];
        using (var sha = SHA256.Create())
        {
            byte[] input = Utils.Encoding.GetBytes(providedPassword);
            byte[] saltedInput = new byte[salt.Length + input.Length];
            salt.CopyTo(saltedInput, 0);
            input.CopyTo(saltedInput, salt.Length);
            byte[] hash = sha.ComputeHash(saltedInput);
            for (int i = 0; i < 99999; i++)
            {
                hash.CopyTo(saltedInput, 0);
                hash = sha.ComputeHash(saltedInput);
            }
            hash.CopyTo(providedDigest, 0);
        }
        if (Utils.EncodeSaltAndDigest(salt, providedDigest) == hashedPassword)
        {
            return PasswordVerificationResult.Success;
        }
        return PasswordVerificationResult.Failed;
    }

}