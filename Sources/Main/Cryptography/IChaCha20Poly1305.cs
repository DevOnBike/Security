using Microsoft.AspNetCore.DataProtection;

namespace DevOnBike.Heimdall.Cryptography
{
    public interface IChaCha20Poly1305
    {
        byte[] Encrypt(ISecret key, byte[] toEncrypt);
        byte[] Decrypt(ISecret key, byte[] toDecrypt);
    }
}

