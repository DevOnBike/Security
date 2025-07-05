using BenchmarkDotNet.Running;
using Benchmarks;

namespace DevOnBike.Security.Benchmarks
{
    internal class Program
    {
        static void Main(string[] args)
        {
            BenchmarkRunner.Run<ChaChaBenchmark>();
        }
    }
}