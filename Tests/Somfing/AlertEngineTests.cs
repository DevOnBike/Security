using DevOnBike.Security.Tests.Somfing.Contracts;

namespace DevOnBike.Security.Tests.Somfing
{
    public class AlertEngineTests
    {
        private static AlertEngine Default() =>
            new(new AlertEngineOptions { ActivationThreshold = 3, RecoveryThreshold = 3, EscalationThresholdSeconds = 0 });

        // ── guard clauses ─────────────────────────────────────────────────

        [Fact]
        public void Constructor_ActivationThresholdZero_Throws()
            => Assert.Throws<ArgumentOutOfRangeException>(() =>
                new AlertEngine(new AlertEngineOptions { ActivationThreshold = 0 }));

        [Fact]
        public void Constructor_RecoveryThresholdZero_Throws()
            => Assert.Throws<ArgumentOutOfRangeException>(() =>
                new AlertEngine(new AlertEngineOptions { RecoveryThreshold = 0 }));

        // ── stan początkowy ───────────────────────────────────────────────

        [Fact]
        public void InitialState_IsHealthyAndNoAlert()
        {
            var engine = Default();
            Assert.False(engine.IsAlertActive);
            Assert.Equal(ServerState.Healthy, engine.CurrentAlertState);
            Assert.Equal(0, engine.ConsecutiveCount);
        }

        // ── aktywacja alertu ──────────────────────────────────────────────

        [Fact]
        public void Process_BelowThreshold_AlertNotActivated()
        {
            var engine = Default();         // threshold = 3
            engine.Process(ServerState.Critical);
            engine.Process(ServerState.Critical);

            Assert.False(engine.IsAlertActive);
            Assert.Equal(ServerState.Healthy, engine.CurrentAlertState);
        }

        [Fact]
        public void Process_AtThreshold_AlertActivated()
        {
            var engine = Default();
            bool fired = false;
            engine.OnAlertActivated += (_, _) => fired = true;

            engine.Process(ServerState.Critical);
            engine.Process(ServerState.Critical);
            engine.Process(ServerState.Critical);   // 3. próbka = próg

            Assert.True(engine.IsAlertActive);
            Assert.True(fired);
            Assert.Equal(ServerState.Critical, engine.CurrentAlertState);
        }

        [Fact]
        public void Process_AlertActivated_EventArgsContainCorrectState()
        {
            var engine = Default();
            AlertActivatedEventArgs? args = null;
            engine.OnAlertActivated += (_, e) => args = e;

            for (int i = 0; i < 3; i++)
                engine.Process(ServerState.Degraded);

            Assert.NotNull(args);
            Assert.Equal(ServerState.Degraded, args!.State);
            Assert.Equal(3, args.ConsecutiveCount);
        }

        // ── odwołanie alertu ──────────────────────────────────────────────

        [Fact]
        public void Process_HealthyAfterAlert_BelowRecoveryThreshold_AlertStillActive()
        {
            var engine = Default();         // recovery = 3
            for (int i = 0; i < 3; i++) engine.Process(ServerState.Critical);

            engine.Process(ServerState.Healthy);
            engine.Process(ServerState.Healthy);    // 2 < 3

            Assert.True(engine.IsAlertActive);
        }

        [Fact]
        public void Process_HealthyAtRecoveryThreshold_AlertResolved()
        {
            var engine = Default();
            bool resolved = false;
            engine.OnAlertResolved += (_, _) => resolved = true;

            for (int i = 0; i < 3; i++) engine.Process(ServerState.Critical);
            for (int i = 0; i < 3; i++) engine.Process(ServerState.Healthy);

            Assert.False(engine.IsAlertActive);
            Assert.True(resolved);
            Assert.Equal(ServerState.Healthy, engine.CurrentAlertState);
        }

        [Fact]
        public void Process_AlertResolved_EventArgsContainDuration()
        {
            var now = DateTimeOffset.UtcNow;
            var engine = Default();
            AlertResolvedEventArgs? args = null;
            engine.OnAlertResolved += (_, e) => args = e;

            for (int i = 0; i < 3; i++)
                engine.Process(ServerState.Critical, now.AddSeconds(i));

            for (int i = 0; i < 3; i++)
                engine.Process(ServerState.Healthy, now.AddSeconds(3 + i));

            Assert.NotNull(args);
            Assert.Equal(ServerState.Critical, args!.PreviousState);
            Assert.True(args.Duration.TotalSeconds >= 0);
        }

        // ── reset licznika recovery przy nawrocie ─────────────────────────

        [Fact]
        public void Process_HealthyInterruptedByNonHealthy_RecoveryCounterResets()
        {
            var engine = Default();
            for (int i = 0; i < 3; i++) engine.Process(ServerState.Critical);

            engine.Process(ServerState.Healthy);
            engine.Process(ServerState.Healthy);
            engine.Process(ServerState.Critical);   // przerywa recovery
            engine.Process(ServerState.Healthy);
            engine.Process(ServerState.Healthy);    // tylko 2 × Healthy po przerwaniu

            Assert.True(engine.IsAlertActive, "Alert powinien być nadal aktywny — recovery nie dobiegło końca.");
        }

        // ── eskalacja ─────────────────────────────────────────────────────

        [Fact]
        public void Process_AlertActiveForEscalationThreshold_EscalationFired()
        {
            var opts = new AlertEngineOptions
            {
                ActivationThreshold = 2,
                RecoveryThreshold = 10,
                EscalationThresholdSeconds = 5
            };
            var engine = new AlertEngine(opts);
            bool escalated = false;
            engine.OnAlertEscalated += (_, _) => escalated = true;

            var now = DateTimeOffset.UtcNow;

            engine.Process(ServerState.Critical, now);
            engine.Process(ServerState.Critical, now.AddSeconds(1));   // aktywacja

            // 6 sekund po aktywacji
            engine.Process(ServerState.Critical, now.AddSeconds(7));

            Assert.True(escalated);
        }

        [Fact]
        public void Process_EscalationFiredOnlyOnce()
        {
            var opts = new AlertEngineOptions
            {
                ActivationThreshold = 2,
                RecoveryThreshold = 100,
                EscalationThresholdSeconds = 5
            };
            var engine = new AlertEngine(opts);
            int count = 0;
            engine.OnAlertEscalated += (_, _) => count++;

            var now = DateTimeOffset.UtcNow;
            engine.Process(ServerState.Critical, now);
            engine.Process(ServerState.Critical, now.AddSeconds(1));

            for (int i = 0; i < 10; i++)
                engine.Process(ServerState.Critical, now.AddSeconds(6 + i));

            Assert.Equal(1, count);
        }

        // ── OnStateChanged ────────────────────────────────────────────────

        [Fact]
        public void Process_StateChange_OnStateChangedFired()
        {
            var engine = Default();
            var changes = new List<(ServerState from, ServerState to)>();
            engine.OnStateChanged += (_, e) => changes.Add((e.Previous, e.Current));

            engine.Process(ServerState.Healthy);
            engine.Process(ServerState.Degraded);
            engine.Process(ServerState.Critical);
            engine.Process(ServerState.Healthy);

            Assert.Equal(3, changes.Count);
            Assert.Equal((ServerState.Healthy, ServerState.Degraded), changes[0]);
            Assert.Equal((ServerState.Degraded, ServerState.Critical), changes[1]);
            Assert.Equal((ServerState.Critical, ServerState.Healthy), changes[2]);
        }

        [Fact]
        public void Process_SameStateRepeated_OnStateChangedNotFired()
        {
            var engine = Default();
            int count = 0;
            engine.OnStateChanged += (_, _) => count++;

            for (int i = 0; i < 5; i++)
                engine.Process(ServerState.Critical);

            Assert.Equal(1, count);  // tylko H→C przy pierwszym
        }

        // ── Reset ─────────────────────────────────────────────────────────

        [Fact]
        public void Reset_ClearsAllState()
        {
            var engine = Default();
            for (int i = 0; i < 3; i++) engine.Process(ServerState.Critical);
            Assert.True(engine.IsAlertActive);

            engine.Reset();

            Assert.False(engine.IsAlertActive);
            Assert.Equal(ServerState.Healthy, engine.CurrentAlertState);
            Assert.Equal(0, engine.ConsecutiveCount);
        }

        [Fact]
        public void Reset_AfterReset_AlertCanBeActivatedAgain()
        {
            var engine = Default();
            for (int i = 0; i < 3; i++) engine.Process(ServerState.Critical);
            engine.Reset();

            bool fired = false;
            engine.OnAlertActivated += (_, _) => fired = true;
            for (int i = 0; i < 3; i++) engine.Process(ServerState.Degraded);

            Assert.True(fired);
        }

        // ── pełny scenariusz ──────────────────────────────────────────────

        [Fact]
        public void FullScenario_SingleSpikeThenSustainedFailure()
        {
            var opts = new AlertEngineOptions { ActivationThreshold = 2, RecoveryThreshold = 2 };
            var engine = new AlertEngine(opts);
            var alerts = new List<string>();
            engine.OnAlertActivated += (_, e) => alerts.Add($"ACTIVATED:{e.State}");
            engine.OnAlertResolved += (_, e) => alerts.Add($"RESOLVED:{e.PreviousState}");

            // 5x Healthy — brak alertu
            for (int i = 0; i < 5; i++) engine.Process(ServerState.Healthy);
            Assert.Empty(alerts);

            // 1x Critical — poniżej progu
            engine.Process(ServerState.Critical);
            Assert.False(engine.IsAlertActive);

            // 1x Healthy — reset licznika
            engine.Process(ServerState.Healthy);

            // 2x Critical — aktywacja
            engine.Process(ServerState.Critical);
            engine.Process(ServerState.Critical);
            Assert.True(engine.IsAlertActive);
            Assert.Single(alerts);
            Assert.Contains("ACTIVATED:Critical", alerts[0]);

            // 2x Healthy — odwołanie
            engine.Process(ServerState.Healthy);
            engine.Process(ServerState.Healthy);
            Assert.False(engine.IsAlertActive);
            Assert.Equal(2, alerts.Count);
            Assert.Contains("RESOLVED:Critical", alerts[1]);
        }
    }
}