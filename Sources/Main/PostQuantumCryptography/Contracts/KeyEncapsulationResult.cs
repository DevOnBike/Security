using DevOnBike.Heimdall.PostQuantumCryptography.Abstractions;

namespace DevOnBike.Heimdall.PostQuantumCryptography.Contracts
{
    /// <summary>
    /// Represents the result of a KEM encapsulation operation.
    /// </summary>
    public class KeyEncapsulationResult : IEncapsulationResult
    {
        public byte[] SharedSecret { get; }

        public byte[] Encapsulation { get; }

        private KeyEncapsulationResult()
        {
            
        }

        private KeyEncapsulationResult(byte[] sharedSecret, byte[] encapsulation)
        {
            SharedSecret = sharedSecret;
            Encapsulation = encapsulation;
        }

        public static KeyEncapsulationResult Create(byte[] sharedSecret, byte[] encapsulation)
        {
            return new KeyEncapsulationResult(sharedSecret, encapsulation);
        }
    }
}

