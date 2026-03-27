namespace DevOnBike.Security.Tests.Somfing
{
    // ════════════════════════════════════════════════════════════════════════
    //  AlertEngine.cs  —  Faza 5: silnik alertów ponad HmmRealTimeMonitor
    //
    //  ODPOWIEDZIALNOŚĆ
    //  ─────────────────────────────────────────────────────────────────────
    //  Przyjmuje surową diagnozę Viterbiego (per-próbka) i zarządza
    //  stanami alertów wg reguł biznesowych:
    //
    //    • Alert aktywowany gdy ten sam stan != Healthy przez N sekund z rzędu
    //    • Alert odwołany gdy Healthy utrzymuje się przez M sekund z rzędu
    //    • Emituje C# events — caller decyduje co z nimi zrobić (PagerDuty, Teams, log)
    //
    //  AUTOMAT STANÓW
    //  ─────────────────────────────────────────────────────────────────────
    //
    //    Idle ──[N razy non-Healthy]──► Alerting
    //    Alerting ──[M razy Healthy]──► Idle
    //    Alerting ──[stan się zmienia]──► OnAlertStateChanged (event)
    //
    //  UŻYCIE
    //  ─────────────────────────────────────────────────────────────────────
    //
    //    var engine = new AlertEngine(new AlertEngineOptions
    //    {
    //        ActivationThreshold  = 10,   // 10s non-Healthy → alert
    //        RecoveryThreshold    = 30,   // 30s Healthy → odwołanie
    //    });
    //
    //    engine.OnAlertActivated  += e => pagerDuty.Trigger(e);
    //    engine.OnAlertResolved   += e => pagerDuty.Resolve(e);
    //    engine.OnAlertEscalated  += e => teams.Post(e);
    //
    //    // W pętli HmmRealTimeMonitor:
    //    ServerState diagnosis = monitor.ProcessNewObservation(metrics);
    //    engine.Process(diagnosis, DateTimeOffset.UtcNow);
    // ════════════════════════════════════════════════════════════════════════

    // ── konfiguracja ──────────────────────────────────────────────────────

    public sealed class AlertEngineOptions
    {
        /// <summary>
        /// Ile kolejnych próbek non-Healthy aktywuje alert. Domyślnie 10.
        /// Przy 1s próbkowania = 10 sekund zanim PagerDuty dostanie ping.
        /// </summary>
        public int ActivationThreshold { get; init; } = 10;

        /// <summary>
        /// Ile kolejnych próbek Healthy odwołuje alert. Domyślnie 30.
        /// </summary>
        public int RecoveryThreshold { get; init; } = 30;

        /// <summary>
        /// Eskalacja: ile sekund w stanie Critical zanim wyemituje OnAlertEscalated.
        /// 0 = eskalacja wyłączona. Domyślnie 60.
        /// </summary>
        public int EscalationThresholdSeconds { get; init; } = 60;
    }
}