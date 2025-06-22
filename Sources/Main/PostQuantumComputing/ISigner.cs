using DevOnBike.Heimdall.PostQuantumComputing.Contracts;

namespace DevOnBike.Heimdall.PostQuantumComputing
{
    public interface ISigner
    {
        byte[] CreateSignature(byte[] data, byte[] key);
        byte[] CreateSignature(byte[] data, PqcKeyPair keyPair);

        public bool VerifySignature(byte[] signature, byte[] key);
    }
}

