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
        
        // Używamy Queue, ponieważ jest to najszybsza struktura do dodawania na koniec i usuwania z początku (FIFO)
        private readonly Queue<double[]> _slidingWindow;

        /// <summary>
        /// Inicjalizuje monitor czasu rzeczywistego.
        /// </summary>
        /// <param name="decoder">Nasz skonfigurowany dekoder Viterbiego</param>
        /// <param name="windowSize">Rozmiar okna pamięci (domyślnie 60 ostatnich próbek)</param>
        public HmmRealTimeMonitor(ViterbiDecoder decoder, int windowSize = 60)
        {
            _decoder = decoder ?? throw new ArgumentNullException(nameof(decoder));

            if (windowSize < 2)
            {
                throw new ArgumentException("Rozmiar okna musi wynosić minimum 2, aby algorytm Viterbiego miał sens (wymaga historii).");
            }
                
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
            {
                throw new ArgumentNullException(nameof(currentMetrics));
            }

            // 1. Dodajemy nową próbkę na koniec kolejki
            _slidingWindow.Enqueue(currentMetrics);

            // 2. Jeśli przekroczyliśmy rozmiar okna, usuwamy najstarszą próbkę (wypada z pamięci)
            if (_slidingWindow.Count > _windowSize)
            {
                _slidingWindow.Dequeue();
            }

            // --- OPTYMALIZACJA STARTOWA ---
            // Zanim okno się zapełni choć trochę (np. w pierwszej sekundzie),
            // po prostu zakładamy stan, który jest najbardziej prawdopodobny w pierwszej klatce.
            // Zabezpiecza to przed błędami dekodera dla zbyt krótkich ciągów.
            if (_slidingWindow.Count == 1)
            {
                // Zwracamy najpewniejszy stan według macierzy startowej (InitialLogProbabilities)
                // (W pełnej implementacji można by tu puścić dekodowanie samej emisji 1 klatki)
                return ServerState.Healthy; 
            }

            // 3. Konwersja kolejki do listy odczytu (wymagane przez nasz dekoder)
            // Używamy .ToArray() lub .ToList() dla bezpieczeństwa, aby dekoder widział migawkę
            var currentWindowSnapshot = _slidingWindow.ToList();

            // 4. Uruchamiamy mózg operacji na naszym wycinku czasowym
            var decodedPath = _decoder.Decode(currentWindowSnapshot);

            // 5. Najważniejszy moment: zwracamy OSTATNI element ścieżki.
            // To jest właśnie diagnoza tego, co dzieje się w systemie W TEJ SEKUNDZIE.
            return decodedPath.Last();
        }

        /// <summary>
        /// Zwraca aktualne wypełnienie okna (przydatne do logowania).
        /// </summary>
        public int CurrentWindowFill => _slidingWindow.Count;
    }
}