namespace DevOnBike.Security.Tests.Somfing.Contracts
{
    public sealed class StateChangedEventArgs(ServerState previous, ServerState current, DateTimeOffset changedAt)
        : EventArgs
    {
        public ServerState Previous { get; } = previous;
        public ServerState Current { get; } = current;
        public DateTimeOffset ChangedAt { get; } = changedAt;
    }
}