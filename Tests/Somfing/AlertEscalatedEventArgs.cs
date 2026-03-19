using DevOnBike.Security.Tests.Somfing.Contracts;
namespace DevOnBike.Security.Tests.Somfing
{
    public sealed class AlertEscalatedEventArgs(ServerState state, DateTimeOffset escalatedAt, TimeSpan activeFor)
        : EventArgs
    {
        public ServerState State { get; } = state;
        public DateTimeOffset EscalatedAt { get; } = escalatedAt;
        /// <summary>Jak długo alert jest aktywny w momencie eskalacji.</summary>
        public TimeSpan ActiveFor { get; } = activeFor;

        public override string ToString() =>
            $"[ESCALATION] {State} aktywny od {ActiveFor:mm\\:ss} @ {EscalatedAt:HH:mm:ss}";
    }
}