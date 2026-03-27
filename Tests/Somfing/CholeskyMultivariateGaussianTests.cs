using DevOnBike.Security.Tests.Somfing.Contracts;

namespace DevOnBike.Security.Tests.Somfing
{
    public class CholeskyMultivariateGaussianTests
    {
        // ====================================================================
        // 1. TESTY KONSTRUKTORA I WALIDACJI (EDGE CASES)
        // ====================================================================

        [Fact]
        public void Constructor_NullMean_ThrowsArgumentNullException()
        {
            double[,] cov =
            {
                {
                    1.0
                }
            };
            Assert.Throws<ArgumentNullException>(() => new CholeskyMultivariateGaussian(null!, cov));
        }

        [Fact]
        public void Constructor_NullCovariance_ThrowsArgumentNullException()
        {
            double[] mean =
            {
                0.0
            };
            Assert.Throws<ArgumentNullException>(() => new CholeskyMultivariateGaussian(mean, null!));
        }

        [Fact]
        public void Constructor_EmptyMean_ThrowsArgumentException()
        {
            var mean = Array.Empty<double>();
            var cov = new double[0, 0];
            Assert.Throws<ArgumentException>(() => new CholeskyMultivariateGaussian(mean, cov));
        }

        [Fact]
        public void Constructor_DimensionMismatch_ThrowsArgumentException()
        {
            double[] mean =
            {
                0.0, 0.0
            };
            double[,] cov =
            {
                {
                    1.0
                }
            }; // 1x1 cov dla 2D mean
            Assert.Throws<ArgumentException>(() => new CholeskyMultivariateGaussian(mean, cov));
        }

        [Fact]
        public void Constructor_NonPositiveDefiniteCovariance_ThrowsArgumentException()
        {
            double[] mean =
            {
                0.0, 0.0
            };
            // Macierz, która nie jest dodatnio określona (kolumny są idealnie skorelowane lub zera)
            double[,] cov =
            {
                {
                    1.0, 2.0
                },
                {
                    2.0, 1.0
                }
            };

            var ex = Assert.Throws<ArgumentException>(() => new CholeskyMultivariateGaussian(mean, cov));
            Assert.Contains("nie jest dodatnio określona", ex.Message);
        }

        // ====================================================================
        // 2. TESTY WALIDACJI OBSERWACJI
        // ====================================================================

        [Fact]
        public void LogProbabilityDensity_NullObservation_ThrowsArgumentException()
        {
            var model = CreateStandard1DModel();
            Assert.Throws<ArgumentException>(() => model.LogProbabilityDensity(null!));
        }

        [Fact]
        public void LogProbabilityDensity_WrongDimension_ThrowsArgumentException()
        {
            var model = CreateStandard1DModel();
            double[] obs =
            {
                0.0, 0.0
            }; // Model 1D, obserwacja 2D
            Assert.Throws<ArgumentException>(() => model.LogProbabilityDensity(obs));
        }

        // ====================================================================
        // 3. TESTY POPRAWNOŚCI MATEMATYCZNEJ
        // ====================================================================

        [Fact]
        public void ProbabilityDensity_StandardNormal1D_ReturnsCorrectValue()
        {
            // Arrange: Standardowy rozkład normalny N(0, 1)
            var model = CreateStandard1DModel();
            double[] observation =
            {
                0.0
            }; // x = 0

            // Act
            var p = model.ProbabilityDensity(observation);

            // Assert
            // Wartość teoretyczna dla N(0,1) w x=0 to 1/sqrt(2*pi) ≈ 0.39894228
            var expected = 1.0 / Math.Sqrt(2.0 * Math.PI);
            Assert.Equal(expected, p, precision: 6);
        }

        [Fact]
        public void LogProbabilityDensity_MatchesMathLogOfProbabilityDensity()
        {
            var model = CreateStandard1DModel();
            double[] observation =
            {
                1.5
            }; // Jakaś wartość x

            var logP = model.LogProbabilityDensity(observation);
            var p = model.ProbabilityDensity(observation);

            Assert.Equal(Math.Log(p), logP, precision: 6);
        }

        [Fact]
        public void ProbabilityDensity_Independent2D_ReturnsProductOf1D()
        {
            // Arrange: 2D Gauss z niezależnymi zmiennymi
            double[] mean =
            {
                0.0, 0.0
            };
            double[,] cov =
            {
                {
                    1.0, 0.0
                },
                {
                    0.0, 1.0
                }
            };
            var model2D = new CholeskyMultivariateGaussian(mean, cov);

            var model1D = CreateStandard1DModel();

            double[] obs2D =
            {
                1.0, -0.5
            };

            // Act
            var p2D = model2D.ProbabilityDensity(obs2D);
            var p1Dx = model1D.ProbabilityDensity(new[]
            {
                obs2D[0]
            });
            var p1Dy = model1D.ProbabilityDensity(new[]
            {
                obs2D[1]
            });

            // Assert: Skoro zmienne są niezależne (cov[0,1] = 0), p(x,y) = p(x)*p(y)
            Assert.Equal(p1Dx * p1Dy, p2D, precision: 6);
        }

        [Fact]
        public void GetLogProbability_InterfaceImplementation_ReturnsSameAsLogProbabilityDensity()
        {
            // Arrange
            IEmissionModel model = CreateStandard1DModel();
            double[] obs =
            {
                0.75
            };

            // Act
            var interfaceLog = model.GetLogProbability(obs);
            var concreteLog = ((CholeskyMultivariateGaussian)model).LogProbabilityDensity(obs);

            // Assert
            Assert.Equal(concreteLog, interfaceLog, precision: 10);
        }

        // ====================================================================
        // HELPERY
        // ====================================================================

        private CholeskyMultivariateGaussian CreateStandard1DModel()
        {
            double[] mean =
            {
                0.0
            };
            double[,] cov =
            {
                {
                    1.0
                }
            };
            return new CholeskyMultivariateGaussian(mean, cov);
        }
    }
}