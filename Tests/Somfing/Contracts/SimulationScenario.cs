namespace DevOnBike.Security.Tests.Somfing.Contracts
{
    public enum SimulationScenario
    {
        Healthy,
        MemoryLeak,
        CpuSpike,
        Cascade,
        /// <summary>Healthy(30s) → CpuSpike(20s) → MemoryLeak(20s) → Cascade(10s) → Recovery(30s)</summary>
        FullIncident
    }
}