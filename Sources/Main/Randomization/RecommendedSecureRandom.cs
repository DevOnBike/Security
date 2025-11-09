using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace DevOnBike.Heimdall.Randomization
{
    public class RecommendedSecureRandom
    {
        public static readonly SecureRandom Instance = Build();
        
        private static SecureRandom Build()
        {
            // Prediction Resistance: Set to 'true' for most cryptographic uses.
            //    This tells the DRBG to reseed itself frequently by drawing fresh
            //    entropy from the entropy source. This makes it much harder for an
            //    adversary to predict future outputs even if they somehow compromise
            //    the DRBG's internal state at one point in time.
            const bool predictionResistant = true;
            
            // 1. Entropy Source:
            //    It's crucial to have a strong, entropy source.
            //    Bouncy Castle's default SecureRandom (obtained via new SecureRandom())
            //    attempts to use the underlying OS's cryptographically secure PRNG (CSPRNG).
            //    This is usually sufficient. For very high-security scenarios or
            //    specific environments, you might consider a custom IEntropySourceProvider
            //    that draws from hardware RNGs or other dedicated entropy sources.
            var entropySourceProvider = new BasicEntropySourceProvider(new SecureRandom(), true);

            // 2. Block Cipher: AES is the recommended choice for modern applications.
            //    Use a strong key size, typically AES-256.
            var cipher = AesUtilities.CreateEngine();
            const int keySizeInBits = 256; // AES-256

            // 3. Nonce (initial vector):
            //    This must be truly unique for each *instantiation* of the DRBG.
            //    It helps to ensure that if you create multiple SecureRandom instances,
            //    their initial states are distinct, even if seeded at similar times.
            //    The nonce size should generally match the block size of the cipher.
            var nonce = new byte[cipher.GetBlockSize()];

            // Get random bytes for the nonce from a good entropy source.
            // You can use the initial entropy source's SecureRandom for this.
            // Or, if using the default BouncyCastle SecureRandom directly for the builder,
            // you could use an independent SecureRandom for just the nonce.
            RandomNumberGenerator.Fill(nonce);

            return new SP800SecureRandomBuilder(entropySourceProvider)
                .SetPersonalizationString("DevOnBike.Heimdall"u8.ToArray())
                .BuildCtr(cipher, keySizeInBits, nonce, predictionResistant);
        }
    }
}