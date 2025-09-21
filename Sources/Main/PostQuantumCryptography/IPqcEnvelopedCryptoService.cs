using DevOnBike.Heimdall.PostQuantumCryptography.Contracts;

namespace DevOnBike.Heimdall.PostQuantumCryptography
{
    public interface IPqcEnvelopedCryptoService
    {
        PqcEnvelopedEncryptedData Encrypt(byte[] toEncrypt, byte[] aad);

        byte[] Decrypt(PqcEnvelopedEncryptedData encrypted);
    }
}