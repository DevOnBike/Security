using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using DevOnBike.Heimdall.Cryptography.Abstractions;
using DevOnBike.Heimdall.Cryptography.Contracts;
using DevOnBike.Heimdall.Randomization;


namespace DevOnBike.Heimdall.PostQuantumCryptography
{
    public sealed class MicrosoftMlKemKeysGenerator : IAsymmetricKeyPairGenerator
    {
        private readonly MLKemAlgorithm _parameters;
        private readonly IRandom _random;

        public MicrosoftMlKemKeysGenerator(IRandom random, MLKemAlgorithm keyGenerationParameters)
        {
            _random = random;
            _parameters = keyGenerationParameters;
        }

        public MicrosoftMlKemKeysGenerator() : this(DefaultRandom.Instance, MLKemAlgorithm.MLKem768)
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