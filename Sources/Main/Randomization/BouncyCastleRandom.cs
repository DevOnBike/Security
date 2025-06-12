using AesUtilities = Org.BouncyCastle.Crypto.AesUtilities;
using SP800SecureRandom = Org.BouncyCastle.Crypto.Prng.SP800SecureRandom;
using SP800SecureRandomBuilder = Org.BouncyCastle.Crypto.Prng.SP800SecureRandomBuilder;

namespace DevOnBike.Heimdall.Randomization
{
    public class BouncyCastleRandom : IRandom
    {
        private static readonly SP800SecureRandom _generator = new SP800SecureRandomBuilder()
            .BuildCtr(AesUtilities.CreateEngine(), 256, Guid.NewGuid().ToByteArray(), false);
                
        public int Next()
        {
            return _generator.Next();
        }

        public void Fill(byte[] toFill)
        {
            _generator.NextBytes(toFill);
        }
        
        public void Fill(Span<byte> toFill)
        {
            _generator.NextBytes(toFill);
        }

        public byte[] GenerateSeed(int numBytes)
        {
            if (numBytes < 2)
            {
                throw new ArgumentOutOfRangeException(nameof(numBytes), "Seed length should be > 0");
            }

            return _generator.GenerateSeed(numBytes);
        }
    }
}

