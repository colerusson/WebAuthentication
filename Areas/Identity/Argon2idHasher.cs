using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Konscious.Security.Cryptography;
using System.Text;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by Argon2id.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class Argon2idHasher : IPasswordHasher<IdentityUser>
{

    /// <summary>
    /// Hash a password using Argon2id.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password)
    {
        // todo: Use a random 32-byte salt. Use a 32-byte digest.
        // todo: Degrees of parallelism is 8, iterations is 4, and memory size is 128MB.
        // todo: Encode as "Base64(salt):Base64(digest)"
        byte[] salt = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        byte[] digest = new byte[32];
        using (var argon2 = new Argon2id(Encoding.ASCII.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 8,
            Iterations = 4,
            MemorySize = 128 * 1024
        })
        {
            digest = argon2.GetBytes(32);
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
        using (var argon2 = new Argon2id(Encoding.ASCII.GetBytes(providedPassword))
        {
            Salt = salt,
            DegreeOfParallelism = 8,
            Iterations = 4,
            MemorySize = 128 * 1024
        })
        {
            byte[] providedDigest = argon2.GetBytes(32);
            if (Utils.EncodeSaltAndDigest(salt, providedDigest) == hashedPassword)
            {
                return PasswordVerificationResult.Success;
            }
        }
        return PasswordVerificationResult.Failed;
    }

}