using System.Security.Cryptography;
using DevOnBike.Heimdall.Cryptography.Abstractions;

namespace DevOnBike.Heimdall.Cryptography
{
    /// <summary>
    /// An implementation of IKeyDerivationFunction using the NIST SP 800-108
    /// HMAC-based KDF in Counter Mode, available in .NET.
    /// </summary>
    public sealed class Sp800108HmacCounterKeyDerivationFunction : IKeyDerivationFunction
    {
        private readonly HashAlgorithmName _hashAlgorithm;

        public Sp800108HmacCounterKeyDerivationFunction(HashAlgorithmName hashAlgorithm)
        {
            _hashAlgorithm = hashAlgorithm;
        }

        public Sp800108HmacCounterKeyDerivationFunction() : this(HashAlgorithmName.SHA256)
        {
        }

        /// <inheritdoc />
        public byte[] DeriveKey(
            ReadOnlySpan<byte> ikm,
            int outputLength,
            ReadOnlySpan<byte> label,
            ReadOnlySpan<byte> context)
        {
            if (outputLength <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(outputLength), "Output length must be positive.");
            }

            using var kdf = new SP800108HmacCounterKdf(ikm, _hashAlgorithm);

            return kdf.DeriveKey(label, context, outputLength);
        }
    }
}
