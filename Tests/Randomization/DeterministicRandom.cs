using DevOnBike.Heimdall.Randomization;

namespace DevOnBike.Security.Tests.Randomization
{
    /// <summary>
    /// A deterministic "random" provider that returns a predictable nonce.
    /// This is crucial for creating repeatable tests in cryptography.
    /// </summary>
    public class DeterministicRandom : IRandom
    {
        private readonly byte[] _bytesToReturn;
        
        public DeterministicRandom(byte[] bytesToReturn)
        {
            _bytesToReturn = bytesToReturn;
        }

        public int Next()
        {
            return 0;
        }

        public void Fill(byte[] toFill)
        {
            _bytesToReturn.CopyTo(toFill, 0);
        }

        public void Fill(Span<byte> toFill)
        {
            _bytesToReturn.CopyTo(toFill);
        }

        public byte[] GenerateSeed(int numBytes)
        {
            return [];
        }
    }
}