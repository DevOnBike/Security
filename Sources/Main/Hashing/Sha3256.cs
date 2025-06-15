using System.Security.Cryptography;

namespace DevOnBike.Heimdall.Hashing
{
    /// <summary>
    /// hashing implementation using the SHA3-256 algorithm.
    /// </summary>
    public sealed class Sha3256 : IRecommendedHasher
    {
        public string Id => "SHA3-256";

        /// <inheritdoc />
        public int HashSizeInBytes => SHA3_256.HashSizeInBytes;

        public static readonly Sha3256 Instance = new();

        /// <inheritdoc />
        public byte[] Hash(ReadOnlySpan<byte> source)
        {
            return SHA3_256.HashData(source);
        }

        /// <inheritdoc />
        public ValueTask<byte[]> HashAsync(Stream source, CancellationToken cancellation)
        {
            return SHA3_256.HashDataAsync(source, cancellation);
        }
    }
}