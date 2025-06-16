using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Order;

namespace DevOnBike.Security.Benchmarks
{
    [SimpleJob(RuntimeMoniker.Net90)]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [MemoryDiagnoser]
    [GcForce]
    public class CryptorBenchmark
    {
        [Params(10, 100, 1000)] 
        public int Size { get; set; }

        [Benchmark(Baseline = true)]
        public void BaseHash()
        {

        }

        [Benchmark]
        public void Improved()
        {

        }

        [GlobalSetup]
        public void GlobalSetup()
        {
        }

    }
}