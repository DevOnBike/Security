using Microsoft.AspNetCore.DataProtection;

namespace DevOnBike.Heimdall.Cryptography.Abstractions
{
    public interface IChaCha20Poly1305
    {
        byte[] Encrypt(ISecret key, byte[] toEncrypt);
        byte[] Decrypt(ISecret key, byte[] toDecrypt);
    }
}

