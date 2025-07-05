using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DevOnBike.Heimdall.Cryptography.Abstractions
{
    /// <summary>
    /// Defines a generic interface for a Key Derivation Function (KDF).
    /// </summary>
    public interface IKeyDerivationFunction
    {
        /// <summary>
        /// Derives a key of a specified length from the input keying material.
        /// </summary>
        /// <param name="ikm">Input Keying Material: The initial secret to derive the key from.</param>
        /// <param name="outputLength">The desired length of the derived key in bytes.</param>
        /// <param name="label">
        /// A public value that identifies the purpose for the derived keying material.
        /// Also known as "Info" in other KDFs like HKDF.
        /// </param>
        /// <param name="context">
        /// A public value containing information related to the key agreement.
        /// </param>
        /// <returns>The derived key as a byte array.</returns>
        byte[] DeriveKey(
            ReadOnlySpan<byte> ikm,
            int outputLength,
            ReadOnlySpan<byte> label,
            ReadOnlySpan<byte> context);
    }
}
