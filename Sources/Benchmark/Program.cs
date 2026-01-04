using BenchmarkDotNet.Running;
using Benchmarks;

namespace DevOnBike.Security.Benchmarks
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            // BenchmarkRunner.Run<ChaChaBenchmark>();
            BenchmarkRunner.Run<XChaChaBenchmark>();
        }
    }
}