using DevOnBike.Heimdall.Cryptography.Abstractions;

namespace DevOnBike.Heimdall.PostQuantumComputing.Abstractions
{
    public interface ISigner
    {
        byte[] CreateSignature(byte[] data, byte[] key);
        byte[] CreateSignature(byte[] data, IAsymmetricKeyPair keyPair);

        public bool VerifySignature(byte[] signature, byte[] key);
    }
}

