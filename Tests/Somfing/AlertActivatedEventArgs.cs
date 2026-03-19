using DevOnBike.Security.Tests.Somfing.Contracts;

namespace DevOnBike.Security.Tests.Somfing
{
    // ── event args ────────────────────────────────────────────────────────

    public sealed class AlertActivatedEventArgs(ServerState state, DateTimeOffset triggeredAt, int consecutiveCount)
        : EventArgs
    {
        /// <summary>Stan który wywołał alert (Degraded lub Critical).</summary>
        public ServerState State { get; } = state;
        
        public DateTimeOffset TriggeredAt { get; } = triggeredAt;
        
        /// <summary>Ile próbek z rzędu w tym stanie przed aktywacją.</summary>
        public int ConsecutiveCount { get; } = consecutiveCount;

        public override string ToString() => $"[ALERT] {State} od {ConsecutiveCount} próbek @ {TriggeredAt:HH:mm:ss}";
    }

    // ── silnik alertów ────────────────────────────────────────────────────

}