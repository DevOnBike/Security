using System.Runtime.CompilerServices;
using static DevOnBike.Heimdall.Cryptography.ChaCha20Constants;

namespace DevOnBike.Heimdall.Cryptography
{
    public abstract class AbstractChaCha20Poly1305
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected virtual byte[] CreateNonceBuffer()
        {
            return new byte[NonceSizeInBytes];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected virtual byte[] CreateTagBuffer()
        {
            return new byte[TagSizeInBytes];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected virtual byte[] CreateKeyBuffer()
        {
            return new byte[KeySizeInBytes];
        }

        protected virtual void ExtractNonce(byte[] encrypted, byte[] nonce)
        {
            // nonce + tag + encrypted
            Buffer.BlockCopy(encrypted, 0, nonce, 0, NonceSizeInBytes);
        }

        protected virtual void ExtractTag(byte[] encrypted, byte[] tag)
        {
            // nonce + tag + encrypted
            Buffer.BlockCopy(encrypted, NonceSizeInBytes, tag, 0, TagSizeInBytes);
        }

        protected virtual void ExtractData(byte[] encrypted, byte[] data)
        {
            // nonce + tag + encrypted
            Buffer.BlockCopy(encrypted, NonceSizeInBytes + TagSizeInBytes, data, 0, GetDataLength(encrypted));
        }

        protected virtual int GetDataLength(byte[] encrypted)
        {
            // nonce + tag + encrypted
            return encrypted.Length - NonceSizeInBytes - TagSizeInBytes;
        }

        protected virtual int GetEncryptionTotalLength(byte[] toEncrypt)
        {
            // nonce + tag + encrypted
            return toEncrypt.Length + NonceSizeInBytes + TagSizeInBytes;
        }

        protected virtual void FillNonce(byte[] output, byte[] nonce)
        {
            // nonce + tag + encrypted
            Buffer.BlockCopy(nonce, 0, output, 0, NonceSizeInBytes);
        }

        protected virtual void FillTag(byte[] output, byte[] tag)
        {
            // nonce + tag + encrypted
            Buffer.BlockCopy(tag, 0, output, 0, NonceSizeInBytes);
        }

        protected virtual void FillTag(byte[] output, ReadOnlySpan<byte> tag)
        {
            // nonce + tag + encrypted
            var span = output.AsSpan(NonceSizeInBytes, TagSizeInBytes);

            tag.CopyTo(span);
        }

        protected virtual void FillData(byte[] output, byte[] data)
        {
            // nonce + tag + encrypted
            Buffer.BlockCopy(data, 0, output, NonceSizeInBytes + TagSizeInBytes, data.Length);
        }

        protected virtual void FillData(byte[] output, ReadOnlySpan<byte> data)
        {
            // nonce + tag + encrypted

            var span = output.AsSpan(NonceSizeInBytes + TagSizeInBytes);

            data.CopyTo(span);
        }
    }
}

