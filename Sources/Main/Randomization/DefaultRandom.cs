using System.Security.Cryptography;

namespace DevOnBike.Heimdall.Randomization
{
    /// <summary>
    /// Provides cryptographically secure random numbers by wrapping the
    /// System.Security.Cryptography.RandomNumberGenerator.
    /// This is the recommended implementation of IRandom for production use.
    /// </summary>
    public class DefaultRandom : IRandom
    {
        public int Next()
        {
            // Use RandomNumberGenerator to get 4 bytes of secure random data.
            var randomBytes = new byte[4];
            
            RandomNumberGenerator.Fill(randomBytes);

            // Convert the bytes to an integer.
            var value = BitConverter.ToInt32(randomBytes, 0);

            // To ensure the result is non-negative, we can use the bitwise AND
            // to turn off the sign bit. This is slightly more performant than Math.Abs().
            return value & int.MaxValue;
        }

        public void Fill(byte[] toFill)
        {
            RandomNumberGenerator.Fill(toFill);
        }

        public void Fill(Span<byte> toFill)
        {
            RandomNumberGenerator.Fill(toFill);
        }

        public byte[] GenerateSeed(int numBytes)
        {
            var seed = new byte[numBytes];
            
            RandomNumberGenerator.Fill(seed);
            
            return seed;
        }
    }
}