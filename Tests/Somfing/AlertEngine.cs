using DevOnBike.Security.Tests.Somfing.Contracts;
namespace DevOnBike.Security.Tests.Somfing
{
    /// <summary>
    /// Automat stanów alertów nad diagnozami HMM.
    /// Thread-safe dla single-producer (jeden wątek wywołuje Process).
    /// </summary>
    public sealed class AlertEngine
    {
        private readonly AlertEngineOptions _opts;

        // ── stan automatu ─────────────────────────────────────────────────

        private ServerState _lastDiagnosis = ServerState.Healthy;
        private ServerState _currentAlertState = ServerState.Healthy;
        private int _consecutiveCount = 0;
        private int _recoveryCount = 0;
        private bool _alertActive = false;
        private DateTimeOffset _alertActivatedAt;
        private bool _escalated = false;

        // ── events ───────────────────────────────────────────────────────

        /// <summary>
        /// Wywoływany gdy stan przechodzi Idle → Alerting.
        /// Podepnij tu: PagerDuty trigger, Slack/Teams webhook, zapis do bazy.
        /// </summary>
        public event EventHandler<AlertActivatedEventArgs>? OnAlertActivated;

        /// <summary>
        /// Wywoływany gdy alert zostaje odwołany (Alerting → Idle).
        /// </summary>
        public event EventHandler<AlertResolvedEventArgs>? OnAlertResolved;

        /// <summary>
        /// Wywoływany gdy aktywny alert utrzymuje się dłużej niż EscalationThresholdSeconds.
        /// Jednokrotnie na cykl alertu.
        /// </summary>
        public event EventHandler<AlertEscalatedEventArgs>? OnAlertEscalated;

        /// <summary>
        /// Wywoływany przy każdej zmianie stanu Viterbi (niezależnie od alertu).
        /// Przydatny do dashboardów i logowania.
        /// </summary>
        public event EventHandler<StateChangedEventArgs>? OnStateChanged;

        // ── właściwości inspekcji ─────────────────────────────────────────

        public bool IsAlertActive => _alertActive;
        public ServerState CurrentAlertState => _currentAlertState;
        public int ConsecutiveCount => _consecutiveCount;

        // ── konstruktor ───────────────────────────────────────────────────

        public AlertEngine(AlertEngineOptions? options = null)
        {
            _opts = options ?? new AlertEngineOptions();

            if (_opts.ActivationThreshold < 1)
                throw new ArgumentOutOfRangeException(nameof(options),
                "ActivationThreshold musi być >= 1.");
            if (_opts.RecoveryThreshold < 1)
                throw new ArgumentOutOfRangeException(nameof(options),
                "RecoveryThreshold musi być >= 1.");
        }

        // ── główna metoda ─────────────────────────────────────────────────

        /// <summary>
        /// Przyjmuje jedną diagnozę Viterbiego i aktualizuje stan automatu.
        /// Wywołuj raz per próbka (np. co sekundę) po ProcessNewObservation.
        /// </summary>
        /// <param name="diagnosis">Wynik ViterbiDecoder dla bieżącej próbki.</param>
        /// <param name="timestamp">Czas próbki (domyślnie DateTimeOffset.UtcNow).</param>
        /// <returns>Bieżący stan alertu po przetworzeniu diagnozy.</returns>
        public ServerState Process(ServerState diagnosis, DateTimeOffset? timestamp = null)
        {
            var now = timestamp ?? DateTimeOffset.UtcNow;

            // ── emit OnStateChanged jeśli stan Viterbiego się zmienił ─────
            if (diagnosis != _lastDiagnosis)
            {
                OnStateChanged?.Invoke(this, new StateChangedEventArgs(_lastDiagnosis, diagnosis, now));
                _lastDiagnosis = diagnosis;
                _consecutiveCount = 0;
            }

            _consecutiveCount++;

            if (!_alertActive)
                ProcessIdle(diagnosis, now);
            else
                ProcessAlerting(diagnosis, now);

            return _currentAlertState;
        }

        // ── przejścia automatu ────────────────────────────────────────────

        private void ProcessIdle(ServerState diagnosis, DateTimeOffset now)
        {
            if (diagnosis == ServerState.Healthy)
            {
                _consecutiveCount = 0;
                return;
            }

            // Non-Healthy: sprawdź czy przekroczono próg aktywacji
            if (_consecutiveCount >= _opts.ActivationThreshold)
            {
                _alertActive = true;
                _escalated = false;
                _recoveryCount = 0;
                _alertActivatedAt = now;
                _currentAlertState = diagnosis;

                OnAlertActivated?.Invoke(this, new AlertActivatedEventArgs(
                diagnosis, now, _consecutiveCount));
            }
        }

        private void ProcessAlerting(ServerState diagnosis, DateTimeOffset now)
        {
            if (diagnosis == ServerState.Healthy)
            {
                _recoveryCount++;

                if (_recoveryCount >= _opts.RecoveryThreshold)
                {
                    var duration = now - _alertActivatedAt;
                    var previous = _currentAlertState;

                    _alertActive = false;
                    _escalated = false;
                    _recoveryCount = 0;
                    _consecutiveCount = 0;
                    _currentAlertState = ServerState.Healthy;

                    OnAlertResolved?.Invoke(this, new AlertResolvedEventArgs(previous, now, duration));
                }
                return;
            }

            // Nadal non-Healthy — resetuj licznik recovery
            _recoveryCount = 0;
            _currentAlertState = diagnosis;

            // Eskalacja jeśli przekroczono próg i jeszcze nie eskalowano
            if (_opts.EscalationThresholdSeconds > 0 && !_escalated)
            {
                var activeFor = now - _alertActivatedAt;
                if (activeFor.TotalSeconds >= _opts.EscalationThresholdSeconds)
                {
                    _escalated = true;
                    OnAlertEscalated?.Invoke(this, new AlertEscalatedEventArgs(
                    diagnosis, now, activeFor));
                }
            }
        }

        /// <summary>Resetuje cały stan automatu do wartości początkowych.</summary>
        public void Reset()
        {
            _lastDiagnosis = ServerState.Healthy;
            _currentAlertState = ServerState.Healthy;
            _consecutiveCount = 0;
            _recoveryCount = 0;
            _alertActive = false;
            _escalated = false;
        }
    }
}