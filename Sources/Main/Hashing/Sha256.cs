using System.Security.Cryptography;

namespace DevOnBike.Heimdall.Hashing
{
    /// <summary>
    /// hashing implementation using the SHA3-256 algorithm.
    /// </summary>
    public sealed class Sha256 : IRecommendedHasher
    {
        public string Id => "SHA2-256";

        /// <inheritdoc />
        public int HashSizeInBytes => SHA256.HashSizeInBytes;

        public static readonly Sha256 Instance = new();

        /// <inheritdoc />
        public byte[] Hash(ReadOnlySpan<byte> source)
        {
            return SHA256.HashData(source);
        }

        /// <inheritdoc />
        public ValueTask<byte[]> HashAsync(Stream source, CancellationToken cancellation)
        {
            return SHA256.HashDataAsync(source, cancellation);
        }
    }
}