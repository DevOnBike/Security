using DevOnBike.Security.Tests.Somfing.Contracts;

namespace DevOnBike.Security.Tests.Somfing
{
    public class MetricsSimulatorTests
    {
        // ── IMetricsSource kontrakt ───────────────────────────────────────

        [Fact]
        public void MetricsSimulator_ImplementsIMetricsSource()
        {
            IMetricsSource source = new MetricsSimulator();
            Assert.Equal(4, source.Dimension);
        }

        // ── HasMore ───────────────────────────────────────────────────────

        [Fact]
        public void HasMore_InfiniteMode_AlwaysTrue()
        {
            var sim = new MetricsSimulator(new MetricsSimulatorOptions { SampleCount = 0 });
            Assert.True(sim.HasMore);
        }

        [Fact]
        public async Task HasMore_FiniteMode_FalseAfterAllSamplesRead()
        {
            var sim = new MetricsSimulator(new MetricsSimulatorOptions
            {
                SampleCount = 3,
                SampleInterval = TimeSpan.Zero
            });

            for (int i = 0; i < 3; i++)
            {
                Assert.True(sim.HasMore);
                await sim.ReadNextAsync();
            }

            Assert.False(sim.HasMore);
        }

        // ── wymiar próbki ─────────────────────────────────────────────────

        [Theory]
        [InlineData(SimulationScenario.Healthy)]
        [InlineData(SimulationScenario.MemoryLeak)]
        [InlineData(SimulationScenario.CpuSpike)]
        [InlineData(SimulationScenario.Cascade)]
        [InlineData(SimulationScenario.FullIncident)]
        public async Task ReadNext_AllScenarios_ReturnDimension4(SimulationScenario scenario)
        {
            var sim = new MetricsSimulator(new MetricsSimulatorOptions
            {
                Scenario = scenario,
                SampleInterval = TimeSpan.Zero
            });

            double[] sample = await sim.ReadNextAsync();

            Assert.Equal(4, sample.Length);
        }

        // ── zakres wartości ───────────────────────────────────────────────

        [Fact]
        public async Task ReadNext_AllValues_AreInZeroOneRange()
        {
            var sim = new MetricsSimulator(new MetricsSimulatorOptions
            {
                SampleCount = 100,
                SampleInterval = TimeSpan.Zero,
                NoiseAmplitude = 0.05
            });

            while (sim.HasMore)
            {
                var sample = await sim.ReadNextAsync();
                foreach (double v in sample)
                    Assert.InRange(v, 0.0, 1.0);
            }
        }

        // ── deterministyczność ────────────────────────────────────────────

        [Fact]
        public async Task ReadNext_SameSeed_GivesSameSequence()
        {
            async Task<double[][]> Read(int n)
            {
                var sim = new MetricsSimulator(new MetricsSimulatorOptions
                {
                    SampleCount = n,
                    SampleInterval = TimeSpan.Zero,
                    RandomSeed = 42
                });
                var results = new List<double[]>();
                while (sim.HasMore) results.Add(await sim.ReadNextAsync());
                return [.. results];
            }

            var run1 = await Read(20);
            var run2 = await Read(20);

            for (int i = 0; i < 20; i++)
                for (int d = 0; d < 4; d++)
                    Assert.Equal(run1[i][d], run2[i][d], precision: 14);
        }

        // ── scenariusze: właściwości ──────────────────────────────────────

        [Fact]
        public async Task MemoryLeak_RamIncreasesMonotonically()
        {
            var sim = new MetricsSimulator(new MetricsSimulatorOptions
            {
                Scenario = SimulationScenario.MemoryLeak,
                SampleCount = 30,
                SampleInterval = TimeSpan.Zero,
                NoiseAmplitude = 0.0   // bez szumu dla deterministycznej weryfikacji
            });

            double prevRam = -1;
            while (sim.HasMore)
            {
                var sample = await sim.ReadNextAsync();
                double ram = sample[1];
                Assert.True(ram >= prevRam, $"RAM powinien rosnąć: {prevRam:F4} → {ram:F4}");
                prevRam = ram;
            }
        }

        [Fact]
        public async Task Cascade_AllMetricsIncreaseOverTime()
        {
            var sim = new MetricsSimulator(new MetricsSimulatorOptions
            {
                Scenario = SimulationScenario.Cascade,
                SampleCount = 25,
                SampleInterval = TimeSpan.Zero,
                NoiseAmplitude = 0.0
            });

            double[] first = await sim.ReadNextAsync();
            double[] last = first;
            while (sim.HasMore) last = await sim.ReadNextAsync();

            for (int d = 0; d < 4; d++)
                Assert.True(last[d] > first[d],
                    $"Metryka [{d}]: {first[d]:F3} → {last[d]:F3} powinna wzrosnąć w Cascade.");
        }

        [Fact]
        public async Task Healthy_AllMetricsStayLow()
        {
            var sim = new MetricsSimulator(new MetricsSimulatorOptions
            {
                Scenario = SimulationScenario.Healthy,
                SampleCount = 20,
                SampleInterval = TimeSpan.Zero,
                NoiseAmplitude = 0.005
            });

            while (sim.HasMore)
            {
                var s = await sim.ReadNextAsync();
                Assert.True(s[0] < 0.40, $"CPU={s[0]:F3} powinno być < 0.40 w stanie Healthy");
                Assert.True(s[1] < 0.50, $"RAM={s[1]:F3} powinno być < 0.50 w stanie Healthy");
            }
        }

        // ── cancellation ─────────────────────────────────────────────────

        [Fact]
        public async Task ReadNext_CancelledToken_ThrowsOperationCanceledException()
        {
            var sim = new MetricsSimulator(new MetricsSimulatorOptions
            {
                SampleInterval = TimeSpan.FromSeconds(10)  // długie czekanie
            });
            using var cts = new CancellationTokenSource(millisecondsDelay: 50);

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => sim.ReadNextAsync(cts.Token).AsTask());
        }

        // ── ExpectedState extension ───────────────────────────────────────

        [Theory]
        [InlineData(SimulationScenario.Healthy, 0, ServerState.Healthy)]
        [InlineData(SimulationScenario.Healthy, 50, ServerState.Healthy)]
        [InlineData(SimulationScenario.Cascade, 25, ServerState.Critical)]
        [InlineData(SimulationScenario.FullIncident, 0, ServerState.Healthy)]
        [InlineData(SimulationScenario.FullIncident, 80, ServerState.Healthy)]
        public void ExpectedState_ReturnsCorrectStateForStep(
            SimulationScenario scenario, int step, ServerState expected)
        {
            Assert.Equal(expected, scenario.ExpectedState(step));
        }
    }
}