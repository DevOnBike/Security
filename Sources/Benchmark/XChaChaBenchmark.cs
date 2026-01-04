using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Order;
using DevOnBike.Heimdall.Cryptography;
using DevOnBike.Heimdall.Cryptography.Abstractions;
using DevOnBike.Heimdall.Randomization;
using Microsoft.AspNetCore.DataProtection;

namespace Benchmarks
{
    [SimpleJob(RuntimeMoniker.Net10_0)]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [MemoryDiagnoser]
    [GcForce]
    public class XChaChaBenchmark
    {
        [Params(10, 100, 10_000)] 
        public int Size { get; set; }

        private IXChaCha20Poly1305 bc;
        private IXChaCha20Poly1305 ms;

        private byte[] bytes;
        private ISecret key;

        [Benchmark(Baseline = true)]
        public void BouncyCastleXChacha()
        {
            var encrypted = bc.Encrypt(key, bytes);
        }

        [Benchmark]
        public void MicrosoftXChaCha()
        {
            var encrypted = ms.Encrypt(key, bytes);
        }

        [GlobalSetup]
        public void GlobalSetup()
        {
            var random = new DefaultRandom();

            bytes = new byte[Size];
            
            random.Fill(bytes);
            
            key = CreateChaChaKey();
            bc = new BouncyCastleXChaCha20Poly1305(random);
            ms = new MicrosoftXChaCha20Poly1305(random);
        }

        private static ISecret CreateChaChaKey()
        {
            return new Secret(RandomNumberGenerator.GetBytes(ChaCha20Constants.KeySizeInBytes));
        }
    }
}