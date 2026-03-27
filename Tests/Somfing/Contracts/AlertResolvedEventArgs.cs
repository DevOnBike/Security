namespace DevOnBike.Security.Tests.Somfing.Contracts
{
    public sealed class AlertResolvedEventArgs(ServerState previousState, DateTimeOffset resolvedAt, TimeSpan duration)
        : EventArgs
    {
        public ServerState PreviousState { get; } = previousState;
        public DateTimeOffset ResolvedAt { get; } = resolvedAt;
        /// <summary>Czas trwania alertu od aktywacji do odwołania.</summary>
        public TimeSpan Duration { get; } = duration;

        public override string ToString() =>
            $"[RESOLVED] {PreviousState} zakończony @ {ResolvedAt:HH:mm:ss} (czas trwania: {Duration:mm\\:ss})";
    }
}