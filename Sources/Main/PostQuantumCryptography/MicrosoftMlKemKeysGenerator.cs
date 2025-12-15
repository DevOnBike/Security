using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using DevOnBike.Heimdall.Cryptography.Abstractions;
using DevOnBike.Heimdall.Cryptography.Contracts;

namespace DevOnBike.Heimdall.PostQuantumCryptography
{
    public sealed class MicrosoftMlKemKeysGenerator : IAsymmetricKeyPairGenerator
    {
        private readonly MLKemAlgorithm _parameters;

        public MicrosoftMlKemKeysGenerator(MLKemAlgorithm keyGenerationParameters)
        {
            _parameters = keyGenerationParameters;
        }

        public MicrosoftMlKemKeysGenerator() : this(MLKemAlgorithm.MLKem768)
        {
        }

        /// <inheritdoc />
        [Experimental("SYSLIB5006")]
        public IAsymmetricKeyPair GenerateKeyPair()
        {
            using var kem = MLKem.GenerateKey(_parameters);
            
            return AsymmetricKeyPair.Create(kem);
        }
    }
}