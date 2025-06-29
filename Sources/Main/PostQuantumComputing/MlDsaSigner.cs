using DevOnBike.Heimdall.Cryptography.Abstractions;
using DevOnBike.Heimdall.PostQuantumComputing.Abstractions;
using DevOnBike.Heimdall.PostQuantumComputing.Contracts;
using DevOnBike.Heimdall.Randomization;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DevOnBike.Heimdall.PostQuantumComputing
{
    public class MlDsaSigner : ISigner
    {
        private readonly MLDsaParameters _parameters;
        private readonly SecureRandom _random;

        public MlDsaSigner(SecureRandom random, MLDsaParameters keyGenerationParameters)
        {
            _random = random;
            _parameters = keyGenerationParameters;
        }

        public MlDsaSigner() : this(RecommendedSecureRandom.Instance, MLDsaParameters.ml_dsa_87_with_sha512)
        {
        }
        
        public byte[] CreateSignature(byte[] data, byte[] key)
        {
            var privateKey = MLDsaPrivateKeyParameters.FromEncoding(_parameters, key);
            var signer = SignerUtilities.InitSigner(_parameters.Name, true, privateKey, _random);

            signer.BlockUpdate(data);

            return signer.GenerateSignature();
        }

        public byte[] CreateSignature(byte[] data, IAsymmetricKeyPair keyPair)
        {
            return CreateSignature(data, keyPair.Private.Content);
        }

        public bool VerifySignature(byte[] signature, byte[] key)
        {
            var p = MLDsaPrivateKeyParameters.FromEncoding(_parameters, key);
            var verifier = SignerUtilities.InitSigner(_parameters.Name, forSigning: false, p, null);

            return verifier.VerifySignature(signature);
        }
    }
}

