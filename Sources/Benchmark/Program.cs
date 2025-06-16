using BenchmarkDotNet.Running;

namespace DevOnBike.Security.Benchmarks
{
    internal class Program
    {
        static void Main(string[] args)
        {
            BenchmarkRunner.Run<CryptorBenchmark>();
        }
    }
}