using DevOnBike.Security.Tests.Somfing.Contracts;
namespace DevOnBike.Security.Tests.Somfing
{
    public static class MetricsSimulatorExtensions
    {
        /// <summary>
        /// Zwraca oczekiwany ServerState dla danego kroku symulacji.
        /// Przydatne do weryfikacji w testach integracyjnych.
        /// </summary>
        public static ServerState ExpectedState(this SimulationScenario scenario, int step) =>
            scenario switch
            {
                SimulationScenario.Healthy => ServerState.Healthy,
                SimulationScenario.MemoryLeak => step > 40
                    ? ServerState.Critical : ServerState.Degraded,
                SimulationScenario.CpuSpike => (step % 40) is > 10 and < 30
                    ? ServerState.Degraded : ServerState.Healthy,
                SimulationScenario.Cascade => step > 20
                    ? ServerState.Critical : ServerState.Degraded,
                SimulationScenario.FullIncident => step switch
                {
                    < 30 => ServerState.Healthy,
                    < 50 => ServerState.Degraded,
                    < 70 => ServerState.Degraded,
                    < 80 => ServerState.Critical,
                    _ => ServerState.Healthy
                },
                _ => ServerState.Healthy
            };
    }
}