using DevOnBike.Heimdall.PostQuantumCryptography.Contracts;

namespace DevOnBike.Heimdall.PostQuantumCryptography
{
    public interface IPqcEnvelopedCryptoService
    {
        PqcEncryptedData Encrypt(byte[] toEncrypt);

        byte[] Decrypt(PqcEncryptedData encrypted);
    }
}