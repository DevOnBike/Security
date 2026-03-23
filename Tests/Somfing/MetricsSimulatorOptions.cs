using DevOnBike.Security.Tests.Somfing.Contracts;

namespace DevOnBike.Security.Tests.Somfing
{
    // ════════════════════════════════════════════════════════════════════════
    //  IMetricsSource.cs + MetricsSimulator.cs  —  Faza 5
    //
    //  IMetricsSource  — abstrakcja źródła metryk
    //  MetricsSimulator — deterministyczny generator scenariuszy dla testów
    //
    //  WYMIAR WEKTORA OBSERWACJI (d=4):
    //  ─────────────────────────────────────────────────────────────────────
    //   [0] CPU utilization   0.0–1.0
    //   [1] RAM utilization   0.0–1.0
    //   [2] Latency           znormalizowane (0=0ms, 1=1000ms+)
    //   [3] Error rate        0.0–1.0
    //
    //  SCENARIUSZE SYMULATORA
    //  ─────────────────────────────────────────────────────────────────────
    //   Healthy    — niskie metryki, mały szum
    //   MemoryLeak — RAM rośnie liniowo, pozostałe stabilne
    //   CpuSpike   — CPU skacze, wraca
    //   Cascade    — wszystkie metryki rosną — pod "leży"
    //   Recovery   — łączy scenariusze, symuluje incydent + powrót
    // ════════════════════════════════════════════════════════════════════════

    // ── interfejs ──────────────────────────────────────────────────────────

    // ── opcje symulatora ───────────────────────────────────────────────────

    public sealed class MetricsSimulatorOptions
    {
        public SimulationScenario Scenario { get; init; } = SimulationScenario.Healthy;
        /// <summary>Liczba próbek do wygenerowania. 0 = nieskończona.</summary>
        public int SampleCount { get; init; } = 0;
        /// <summary>Odstęp między próbkami. Domyślnie 1 sekunda.</summary>
        public TimeSpan SampleInterval { get; init; } = TimeSpan.FromSeconds(1);
        /// <summary>Seed RNG. Domyślnie 42 (deterministyczny).</summary>
        public int RandomSeed { get; init; } = 42;
        /// <summary>Amplituda szumu Gaussowskiego na każdej metryce.</summary>
        public double NoiseAmplitude { get; init; } = 0.01;
    }

    // ── symulator ──────────────────────────────────────────────────────────

    // ── etykiety scenariuszy (do logowania i testów) ───────────────────────

}