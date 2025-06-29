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
    [SimpleJob(RuntimeMoniker.Net90)]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [MemoryDiagnoser]
    [GcForce]
    public class ChaChaBenchmark
    {
        [Params(10, 100, 10_000)] 
        public int Size { get; set; }

        private IChaCha20Poly1305 chacha;
        private IXChaCha20Poly1305 xchacha;

        private byte[] bytes;
        private ISecret key;

        [Benchmark(Baseline = true)]
        public void Chacha()
        {
            var encrypted = chacha.Encrypt(key, bytes);
        }

        [Benchmark]
        public void XChaCha()
        {
            var encrypted = xchacha.Encrypt(key, bytes);
        }

        [GlobalSetup]
        public void GlobalSetup()
        {
            var random = new DefaultRandom();

            bytes = new byte[Size];
            
            random.Fill(bytes);
            
            key = CreateChaChaKey();
            chacha = new BouncyCastleChaCha20Poly1305(random);
            xchacha = new BouncyCastleXChaCha20Poly1305(random);
        }

        private ISecret CreateChaChaKey()
        {
            return new Secret(RandomNumberGenerator.GetBytes(ChaCha20Constants.KeySizeInBytes));
        }
    }
}