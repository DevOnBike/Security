using DevOnBike.Security.Tests.Somfing.Contracts;

namespace DevOnBike.Security.Tests.Somfing
{
    /// <summary>
    /// Klasa nasłuchująca w czasie rzeczywistym. 
    /// Utrzymuje okno czasowe (Sliding Window) najnowszych metryk i na bieżąco diagnozuje stan systemu.
    /// </summary>
    public class HmmRealTimeMonitor
    {
        private readonly ViterbiDecoder _decoder;
        private readonly int _windowSize;
        private readonly int _expectedDimension;

        // Używamy Queue, ponieważ jest to najszybsza struktura do dodawania na koniec i usuwania z początku (FIFO)
        private readonly Queue<double[]> _slidingWindow;

        /// <summary>
        /// Log-prawdopodobieństwo ostatnio zdekodowanej ścieżki.
        /// Wartość double.NegativeInfinity oznacza, że diagnoza jest niezaufana
        /// (obserwacja poza zasięgiem wszystkich modeli emisji).
        /// </summary>
        public double LastPathLogProbability { get; private set; } = double.NegativeInfinity;

        /// <summary>
        /// Inicjalizuje monitor czasu rzeczywistego.
        /// </summary>
        /// <param name="decoder">Nasz skonfigurowany dekoder Viterbiego</param>
        /// <param name="expectedDimension">Wymagany wymiar wektora obserwacji (np. 2 dla [CPU, RAM])</param>
        /// <param name="windowSize">Rozmiar okna pamięci (domyślnie 60 ostatnich próbek)</param>
        public HmmRealTimeMonitor(ViterbiDecoder decoder, int expectedDimension, int windowSize = 60)
        {
            _decoder = decoder ?? throw new ArgumentNullException(nameof(decoder));

            if (expectedDimension < 1)
                throw new ArgumentOutOfRangeException(nameof(expectedDimension), "Wymiar obserwacji musi być >= 1.");

            if (windowSize < 1)
            {
                throw new ArgumentException("Rozmiar okna musi wynosić minimum 1.");
            }

            _expectedDimension = expectedDimension;
            _windowSize = windowSize;
            _slidingWindow = new Queue<double[]>(_windowSize);
        }

        /// <summary>
        /// Przyjmuje nową klatkę danych (np. co sekundę) i zwraca aktualnie zdiagnozowany stan ukryty.
        /// </summary>
        /// <param name="currentMetrics">Nowy wektor obserwacji, np. [CPU, RAM]</param>
        /// <returns>Aktualny stan systemu IT</returns>
        public ServerState ProcessNewObservation(double[] currentMetrics)
        {
            if (currentMetrics == null)
                throw new ArgumentNullException(nameof(currentMetrics));

            if (currentMetrics.Length != _expectedDimension)
                throw new ArgumentException(
                $"Wektor metryk ma wymiar {currentMetrics.Length}, oczekiwano {_expectedDimension}. " +
                "Sprawdź czy przekazujesz poprawną liczbę metryk (np. [CPU, RAM]).",
                nameof(currentMetrics));

            // 1. Dodajemy nową próbkę na koniec kolejki
            _slidingWindow.Enqueue(currentMetrics);

            // 2. Jeśli przekroczyliśmy rozmiar okna, usuwamy najstarszą próbkę (wypada z pamięci)
            if (_slidingWindow.Count > _windowSize)
                _slidingWindow.Dequeue();

            // 3. Snapshot kolejki — dekoder widzi niezmienialną kopię okna
            var currentWindowSnapshot = _slidingWindow.ToList();

            // 4. Dekodowanie ścieżki — Viterbi działa poprawnie dla każdego T >= 1
            var decodedPath = _decoder.Decode(currentWindowSnapshot, out var logProb);
            LastPathLogProbability = logProb;

            // 5. Zwracamy OSTATNI element ścieżki — diagnoza dla bieżącej chwili
            return decodedPath.Last();
        }

        /// <summary>
        /// Zwraca aktualne wypełnienie okna (przydatne do logowania).
        /// </summary>
        public int CurrentWindowFill => _slidingWindow.Count;
    }
}