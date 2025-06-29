using System.Runtime.InteropServices;
using System.Security.Cryptography;
using DevOnBike.Heimdall.Hashing.Abstractions;

namespace DevOnBike.Heimdall.Hashing
{
    /// <summary>
    /// hashing implementation using the SHA3-256 algorithm.
    /// Facade version for different platforms
    /// </summary>
    public sealed class Sha3256Facade : IRecommendedHasher
    {
        public string Id => "SHA3-256";

        /// <inheritdoc />
        public int HashSizeInBytes => SHA3_256.HashSizeInBytes;

        public static readonly Sha3256Facade Instance = new();

        /// <inheritdoc />
        public byte[] Hash(ReadOnlySpan<byte> source)
        {
            return GetStrategy().Hash(source);
        }

        /// <inheritdoc />
        public ValueTask<byte[]> HashAsync(Stream source, CancellationToken cancellation)
        {
            return GetStrategy().HashAsync(source, cancellation);
        }
        
        private static IHasher GetStrategy()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return Sha3256.Instance;
            }
            
            return BouncyCastleSha3256.Instance;
        }
    }
}