namespace DevOnBike.Security.Tests.Somfing
{
    /// <summary>
    /// Deterministyczny generator wektorów metryk dla testów i demo.
    /// Implementuje IMetricsSource — można go podstawić zamiast prawdziwego
    /// adaptera Prometheus bez zmiany kodu monitora.
    /// </summary>
    public sealed class MetricsSimulator : IMetricsSource
    {
        private readonly MetricsSimulatorOptions _opts;
        private readonly Random _rng;
        private int _step = 0;

        public int Dimension => 4;  // [CPU, RAM, Latency, ErrorRate]
        public bool HasMore => _opts.SampleCount == 0 || _step < _opts.SampleCount;

        public MetricsSimulator(MetricsSimulatorOptions? options = null)
        {
            _opts = options ?? new MetricsSimulatorOptions();
            _rng = new Random(_opts.RandomSeed);
        }

        /// <inheritdoc/>
        public async ValueTask<double[]> ReadNextAsync(CancellationToken cancellationToken = default)
        {
            if (!HasMore)
                throw new InvalidOperationException("Symulator wyczerpał wszystkie próbki.");

            if (_opts.SampleInterval > TimeSpan.Zero)
                await Task.Delay(_opts.SampleInterval, cancellationToken);

            var sample = GenerateSample(_step);
            _step++;
            return sample;
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        // ── generatory scenariuszy ─────────────────────────────────────────

        private double[] GenerateSample(int step)
        {
            var (cpu, ram, lat, err) = _opts.Scenario switch
            {
                SimulationScenario.Healthy => Healthy(step),
                SimulationScenario.MemoryLeak => MemoryLeak(step),
                SimulationScenario.CpuSpike => CpuSpike(step),
                SimulationScenario.Cascade => Cascade(step),
                SimulationScenario.FullIncident => FullIncident(step),
                _ => throw new ArgumentOutOfRangeException()
            };

            return [
                Clamp(cpu + Noise()),
                Clamp(ram + Noise()),
                Clamp(lat + Noise()),
                Clamp(err + Noise()),
            ];
        }

        /// <summary>CPU~20% RAM~30% Latency~5% Error~1% — stabilna praca.</summary>
        private static (double, double, double, double) Healthy(int step) =>
            (0.20, 0.30, 0.05, 0.01);

        /// <summary>RAM rośnie liniowo ~0.5%/s, reszta stabilna.</summary>
        private static (double, double, double, double) MemoryLeak(int step)
        {
            var ram = Math.Min(0.30 + step * 0.005, 0.98);
            return (0.25, ram, 0.08, 0.02);
        }

        /// <summary>CPU oscyluje między 20% a 90% co 20 sekund.</summary>
        private static (double, double, double, double) CpuSpike(int step)
        {
            var phase = (step % 40) / 40.0 * 2 * Math.PI;
            var cpu = 0.55 + 0.35 * Math.Sin(phase);
            var lat = 0.05 + 0.30 * Math.Max(0, Math.Sin(phase));
            return (cpu, 0.35, lat, 0.02);
        }

        /// <summary>Wszystkie metryki rosną — pełna awaria.</summary>
        private static (double, double, double, double) Cascade(int step)
        {
            var t = Math.Min(step / 30.0, 1.0);
            return (0.50 + 0.45 * t, 0.50 + 0.45 * t, 0.20 + 0.70 * t, 0.05 + 0.30 * t);
        }

        /// <summary>Sekwencja: Healthy → CpuSpike → MemoryLeak → Cascade → Recovery.</summary>
        private static (double, double, double, double) FullIncident(int step) => step switch
        {
            < 30 => Healthy(step),
            < 50 => CpuSpike(step - 30),
            < 70 => MemoryLeak(step - 50),
            < 80 => Cascade(step - 70),
            _ => Healthy(step)          // recovery
        };

        private double Noise() => (_rng.NextDouble() - 0.5) * 2.0 * _opts.NoiseAmplitude;

        private static double Clamp(double v) => Math.Clamp(v, 0.0, 1.0);
    }
}