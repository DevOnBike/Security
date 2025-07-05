using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Utilities;

namespace DevOnBike.Security.Tests.Pqc
{
    public class HybridTests
    {
        [Fact]
        public void HybridKEM_DerivesSameKeyForBothParties()
        {
            // -- Setup EC domain parameters (secp256r1) --
            var ecParams = SecNamedCurves.GetByName("secp256r1");
            var domainParams = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H);

            var keyGen = new ECKeyPairGenerator();
            keyGen.Init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));

            // Generate key pairs for Alice and Bob
            var aliceKp = keyGen.GenerateKeyPair();
            var bobKp = keyGen.GenerateKeyPair();

            // --- Classical ECDH Shared Secret ---
            var ecdhA = new ECDHBasicAgreement();
            ecdhA.Init(aliceKp.Private);
            var sharedA = ecdhA.CalculateAgreement(bobKp.Public);
            var ecdhSecretA = BigIntegers.AsUnsignedByteArray(sharedA);

            var ecdhB = new ECDHBasicAgreement();
            ecdhB.Init(bobKp.Private);
            var sharedB = ecdhB.CalculateAgreement(aliceKp.Public);
            var ecdhSecretB = BigIntegers.AsUnsignedByteArray(sharedB);

            // Ensure ECDH secrets match
            Assert.Equal(ecdhSecretA, ecdhSecretB);

            // --- Simulated PQC shared secret ---
            var pqcShared = new byte[32];
            new SecureRandom().NextBytes(pqcShared);

            // --- Combine and derive final key (HKDF) ---
            var combinedA = ecdhSecretA.Concat(pqcShared).ToArray();
            var combinedB = ecdhSecretB.Concat(pqcShared).ToArray();

            var finalKeyA = DeriveKeyFromCombinedSecret(combinedA);
            var finalKeyB = DeriveKeyFromCombinedSecret(combinedB);

            // Final symmetric key must match
            Assert.Equal(finalKeyA, finalKeyB);
        }

        private byte[] DeriveKeyFromCombinedSecret(byte[] combinedSecret)
        {
            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            hkdf.Init(new HkdfParameters(combinedSecret, null, null));

            var finalKey = new byte[32]; // 256-bit key
            hkdf.GenerateBytes(finalKey, 0, finalKey.Length);
            return finalKey;
        }
    }
}