using System.Security.Cryptography;

namespace DevOnBike.Heimdall.Hashing
{
    /// <summary>
    /// hashing implementation using the SHA3-256 algorithm.
    /// </summary>
    public sealed class Sha3256 : IRecommendedHash
    {
        public string Id => "SHA3-256";

        /// <inheritdoc />
        public int HashSizeInBytes => SHA3_256.HashSizeInBytes;

        /// <inheritdoc />
        public byte[] Hash(ReadOnlySpan<byte> source)
        {
            return SHA3_256.HashData(source);
        }

        public ValueTask<byte[]> HashAsync(Stream source, CancellationToken cancellation)
        {
            return SHA3_256.HashDataAsync(source, cancellation);
        }
    }
}