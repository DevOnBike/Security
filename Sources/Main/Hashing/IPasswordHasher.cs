namespace DevOnBike.Heimdall.Hashing
{
    /// <summary>
    /// Password hasher
    /// </summary>
    public interface IPasswordHasher
    {
        /// <summary>
        /// Hashes a password using PBKDF2 with a randomly generated salt.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <returns>A formatted string containing the hash and all parameters needed for verification.</returns>
        string Hash(string password);

        /// <summary>
        /// Verifies a password attempt against a stored hash string.
        /// </summary>
        /// <param name="password">The password attempt.</param>
        /// <param name="storedHash">The formatted hash string from storage.</param>
        /// <returns>True if the password is correct, otherwise false.</returns>
        public bool VerifyPassword(string password, string storedHash);
    }    
}

