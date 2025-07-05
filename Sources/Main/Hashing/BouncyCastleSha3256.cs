using System.Security.Cryptography;
using DevOnBike.Heimdall.Hashing.Abstractions;
using Org.BouncyCastle.Crypto.Digests;

namespace DevOnBike.Heimdall.Hashing
{
    /// <summary>
    /// hashing implementation using the SHA3-256 algorithm using Bouncy Castle
    /// </summary>
    public sealed class BouncyCastleSha3256 : IHasher
    {
        public string Id => "SHA3-256";

        /// <inheritdoc />
        public int HashSizeInBytes => SHA3_256.HashSizeInBytes;

        public static readonly BouncyCastleSha3256 Instance = new();
        
        /// <inheritdoc />
        public byte[] Hash(ReadOnlySpan<byte> source)
        {
            var digest = Create();
            var hash = CreateBuffer(digest);

            digest.BlockUpdate(source);
            digest.DoFinal(hash, 0);

            return hash;
        }

        /// <inheritdoc />
        public async ValueTask<byte[]> HashAsync(Stream source, CancellationToken cancellation)
        {
            var digest = Create();
            var hash = CreateBuffer(digest);
            
            // Read from the stream in chunks and update the digest.
            var buffer = new byte[4096];
            int bytesRead;
            
            while ((bytesRead = await source.ReadAsync(buffer, cancellation).ConfigureAwait(false)) > 0)
            {
                digest.BlockUpdate(buffer, 0, bytesRead);
            }

            digest.DoFinal(hash, 0);
            
            return hash;
        }
        
        private static Sha3Digest Create()
        {
            return new Sha3Digest(8 * SHA3_256.HashSizeInBytes);
        }
        
        private static byte[] CreateBuffer(Sha3Digest hasher)
        {
            return new byte[hasher.GetDigestSize()];
        }
    }
}