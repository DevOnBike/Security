namespace DevOnBike.Heimdall.Cryptography.Abstractions
{
    public interface ISigner
    {
        byte[] CreateSignature(byte[] data, byte[] key);
        byte[] CreateSignature(byte[] data, IAsymmetricKeyPair keyPair);

        public bool VerifySignature(byte[] signature, byte[] key);
    }
}

