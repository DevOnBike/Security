namespace DevOnBike.Security.Tests.Somfing;

public class CholeskyMultivariateGaussianTests
{
    [Fact]
    public void ProbabilityDensity_StandardNormal_ShouldMatchSciPyReference()
    {
        // ==========================================
        // ARRANGE: Wektor Testowy 1 (Nieskorelowany)
        // ==========================================
        double[] mean = { 0.0, 0.0 };
        double[,] covariance = {
            { 1.0, 0.0 },
            { 0.0, 1.0 }
        };

        var gaussian = new CholeskyMultivariateGaussian(mean, covariance);
        double[] observation = { 0.0, 0.0 }; // Obserwacja w samym centrum "dzwonu"

        // ==========================================
        // ACT
        // ==========================================
        double pdf = gaussian.ProbabilityDensity(observation);

        // ==========================================
        // ASSERT
        // ==========================================
        // Wynik referencyjny wyliczony przez scipy.stats.multivariate_normal w Pythonie
        double expectedPdf = 0.159154943;

        // Tolerancja do 6 miejsc po przecinku (niweluje drobne różnice zaokrągleń między C# a C/Pythonem)
        Assert.Equal(expectedPdf, pdf, precision: 6);
    }

    [Fact]
    public void ProbabilityDensity_CorrelatedMetrics_ShouldMatchSciPyReference()
    {
        // ==========================================
        // ARRANGE: Wektor Testowy 2 (Złożony / Skorelowany)
        // ==========================================
        double[] mean = { 1.0, 2.0 };
        double[,] covariance = {
            { 2.0, 0.5 },
            { 0.5, 1.0 }
        };

        var gaussian = new CholeskyMultivariateGaussian(mean, covariance);
        double[] observation = { 1.5, 1.5 };

        // ==========================================
        // ACT
        // ==========================================
        double pdf = gaussian.ProbabilityDensity(observation);

        // ==========================================
        // ASSERT
        // ==========================================
        // Wynik referencyjny wyliczony przez scipy.stats.multivariate_normal: 0.0904104523...
        double expectedPdf = 0.09041045;

        Assert.Equal(expectedPdf, pdf, precision: 6);
    }

    [Fact]
    public void Constructor_NonPositiveDefiniteMatrix_ShouldThrowArgumentException()
    {
        // ==========================================
        // ARRANGE: Symulacja "zepsutych" danych z k8s
        // Tworzymy macierz, w której wiersze/kolumny są identyczne.
        // Oznacza to brak wariancji lub idealną korelację (wyznacznik = 0).
        // Algorytm Cholesky'ego z definicji obsługuje TYLKO macierze dodatnio określone.
        // ==========================================
        double[] mean = { 1.0, 1.0 };
        double[,] badCovariance = {
            { 1.0, 1.0 },
            { 1.0, 1.0 }
        };

        // ==========================================
        // ACT & ASSERT
        // ==========================================
        // Nasz kod powinien wykryć wartość <= 0 pod pierwiastkiem i rzucić ArgumentException
        var exception = Assert.Throws<ArgumentException>(() =>
            new CholeskyMultivariateGaussian(mean, badCovariance));

        Assert.Contains("nie jest dodatnio określona", exception.Message);
    }
}