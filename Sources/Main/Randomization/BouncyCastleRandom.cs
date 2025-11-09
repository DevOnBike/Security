using Org.BouncyCastle.Security;

namespace DevOnBike.Heimdall.Randomization
{
    public class BouncyCastleRandom : IRandom
    {
        private readonly SecureRandom _generator = RecommendedSecureRandom.Instance;
                
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
            if (numBytes < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(numBytes), "Seed length should be > 0");
            }

            return _generator.GenerateSeed(numBytes);
        }
    }
}

