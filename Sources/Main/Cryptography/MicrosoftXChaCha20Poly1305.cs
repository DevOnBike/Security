using System.Security.Cryptography;
using DevOnBike.Heimdall.Cryptography.Abstractions;
using DevOnBike.Heimdall.Randomization;
using Microsoft.AspNetCore.DataProtection;
using static DevOnBike.Heimdall.Cryptography.XChaCha20Constants; 

namespace DevOnBike.Heimdall.Cryptography
{
    /// <summary>
    /// High-performance implementation of XChaCha20-Poly1305 using .NET primitives.
    /// Optimized for low allocations using StackAlloc and Spans.
    /// </summary>
    public class MicrosoftXChaCha20Poly1305 : AbstractXChaCha20Poly1305, IXChaCha20Poly1305
    {
        private const int InternalNonceSize = 12; // Standard ChaCha20 nonce size (IETF)
        
        private readonly IRandom _random;

        public MicrosoftXChaCha20Poly1305(IRandom random)
        {
            _random = random;
        }

        public byte[] Encrypt(ISecret key, byte[] toEncrypt)
        {
            var output = new byte[GetEncryptionTotalLength(toEncrypt)];

            Span<byte> outputSpan = output;
            
            var nonceSpan = outputSpan.Slice(0, NonceSizeInBytes);
            var tagSpan = outputSpan.Slice(NonceSizeInBytes, TagSizeInBytes);
            var cipherSpan = outputSpan.Slice(NonceSizeInBytes + TagSizeInBytes);

            _random.Fill(nonceSpan);

            Encrypt(key, nonceSpan, toEncrypt, cipherSpan, tagSpan);

            return output;
        }

        public byte[] Decrypt(ISecret key, byte[] toDecrypt)
        {
            // 1. Validate Input
            if (toDecrypt.Length < NonceSizeInBytes + TagSizeInBytes)
            {
                throw new ArgumentException("Ciphertext too short.", nameof(toDecrypt));
            }

            // 2. Slice Input
            ReadOnlySpan<byte> inputSpan = toDecrypt;
            
            var nonceSpan = inputSpan.Slice(0, NonceSizeInBytes);
            var tagSpan = inputSpan.Slice(NonceSizeInBytes, TagSizeInBytes);
            var cipherSpan = inputSpan.Slice(NonceSizeInBytes + TagSizeInBytes);

            // 3. Prepare Output
            var plainText = new byte[cipherSpan.Length];

            // 4. Decrypt Core
            Decrypt(key, nonceSpan, cipherSpan, tagSpan, plainText);

            return plainText;
        }

        private static void Encrypt(
            ISecret key, 
            ReadOnlySpan<byte> xNonce, 
            ReadOnlySpan<byte> toEncrypt, 
            Span<byte> encrypted, 
            Span<byte> tag)
        {
            using var subKey = new SafeByteSpan(stackalloc byte[KeySizeInBytes]);
            using var internalNonce = new SafeByteSpan(stackalloc byte[InternalNonceSize]);
            using var safeKey = new SafeByteArray(new byte[KeySizeInBytes]);
            
            key.Fill(safeKey);

            PrepareChaChaState(safeKey.Span, xNonce, subKey, internalNonce);

            using var chacha = new ChaCha20Poly1305(subKey);
                
            chacha.Encrypt(internalNonce, toEncrypt, encrypted, tag);
        }

        private static void Decrypt(
            ISecret key, 
            ReadOnlySpan<byte> xNonce, 
            ReadOnlySpan<byte> encrypted, 
            ReadOnlySpan<byte> tag, 
            Span<byte> plaintext)
        {
            using var subKey = new SafeByteSpan(stackalloc byte[KeySizeInBytes]);
            using var internalNonce = new SafeByteSpan(stackalloc byte[InternalNonceSize]);
            using var safeKey = new SafeByteArray(new byte[KeySizeInBytes]);

            key.Fill(safeKey);

            PrepareChaChaState(safeKey.Span, xNonce, subKey, internalNonce);

            using var chacha = new ChaCha20Poly1305(subKey);

            chacha.Decrypt(internalNonce, encrypted, tag, plaintext);
        }

        /// <summary>
        /// Shared logic for HChaCha20 subkey derivation and nonce splitting.
        /// </summary>
        private static void PrepareChaChaState(
            ReadOnlySpan<byte> masterKey, 
            ReadOnlySpan<byte> xNonce, 
            Span<byte> subKey,
            Span<byte> internalNonce)
        {
            // 1. HChaCha20: Derive SubKey using MasterKey and first 16 bytes of X-Nonce
            HChaCha20.DeriveSubKey(masterKey, xNonce[..16], subKey);

            // 2. Prepare Internal Nonce (12 bytes) for standard ChaCha20Poly1305
            // Format: [4 bytes 0x00] + [Last 8 bytes of X-Nonce]
            // Note: stackalloc memory is not guaranteed to be zeroed, so we clear it.
            internalNonce.Clear();

            xNonce.Slice(16, 8).CopyTo(internalNonce.Slice(4));
        }
    }
}