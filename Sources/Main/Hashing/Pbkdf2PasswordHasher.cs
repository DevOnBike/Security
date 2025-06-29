using System.Security.Cryptography;
using DevOnBike.Heimdall.Hashing.Abstractions;
using DevOnBike.Heimdall.Randomization;
using Microsoft.Extensions.Options;

namespace DevOnBike.Heimdall.Hashing
{
    /// <summary>
    /// Provides NIST-compliant password hashing and verification using PBKDF2.
    /// </summary>
    public class Pbkdf2PasswordHasher : IRecommendedPasswordHasher
    {
        private readonly IOptions<PasswordHasherOptions> _options;
        private readonly IRandom _random;

        private readonly HashAlgorithmName _hashAlgorithm;

        public Pbkdf2PasswordHasher(
            IOptions<PasswordHasherOptions> options,
            HashAlgorithmName hashAlgorithm,
            IRandom random)
        {
            _options = options;
            _hashAlgorithm = hashAlgorithm;
            _random = random;
        }

        public Pbkdf2PasswordHasher(IRandom random)
            : this(Options.Create(PasswordHasherOptions.Default), HashAlgorithmName.SHA256, random)
        {
            _random = random;
        }

        public string Hash(string password)
        {
            var options = _options.Value;

            // 1. Generate a cryptographically secure random salt.
            var salt = new byte[options.SaltSize];
            _random.Fill(salt);

            // 2. Hash the password using the salt and configured parameters.
            var hash = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                options.Iterations,
                _hashAlgorithm,
                options.HashSize);

            // 3. Combine the salt and hash into a single string for storage.
            // Format: ITERATIONS;SALT;HASH (all parts are Base64 encoded)
            return $"{options.Iterations}{options.Delimiter}{Convert.ToBase64String(salt)}{options.Delimiter}{Convert.ToBase64String(hash)}";
        }

        public bool Verify(string password, string storedHash)
        {
            try
            {
                var options = _options.Value;
                // 1. Split the stored hash string into its components.
                var parts = storedHash.Split(options.Delimiter);
                
                if (parts.Length != 3)
                {
                    // Invalid hash format.
                    return false;
                }

                // 2. Extract the parameters used for the original hash.
                var iterations = int.Parse(parts[0]);
                var salt = Convert.FromBase64String(parts[1]);
                var hash = Convert.FromBase64String(parts[2]);

                // 3. Re-hash the password attempt using the *exact same* parameters.
                var hashToVerify = Rfc2898DeriveBytes.Pbkdf2(
                    password,
                    salt,
                    iterations,
                    _hashAlgorithm,
                    hash.Length); // Use the length of the stored hash.

                // 4. Perform a constant-time comparison to prevent timing attacks.
                return CryptographicOperations.FixedTimeEquals(hashToVerify, hash);
            }
            catch (Exception)
            {
                // If any part of the process fails (e.g., invalid Base64 string),
                // it's an invalid hash.
                return false;
            }
        }
    }
}