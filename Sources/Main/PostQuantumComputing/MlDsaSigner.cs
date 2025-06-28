using DevOnBike.Heimdall.PostQuantumComputing.Contracts;
using DevOnBike.Heimdall.Randomization;
using Org.BouncyCastle.Asn1.Nist;
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
            var p = MLDsaPrivateKeyParameters.FromEncoding(_parameters, key);
            var signer = SignerUtilities.InitSigner(_parameters.Name, forSigning: true, p, _random);

            signer.BlockUpdate(data);

            return signer.GenerateSignature();
        }

        public byte[] CreateSignature(byte[] data, PqcKeyPair keyPair)
        {
            return CreateSignature(data, keyPair.PrivateKey);
        }

        public bool VerifySignature(byte[] signature, byte[] key)
        {
            var p = MLDsaPrivateKeyParameters.FromEncoding(_parameters, key);
            var verifier = SignerUtilities.InitSigner(_parameters.Name, forSigning: false, p, null);

            return verifier.VerifySignature(signature);
        }
    }
}

