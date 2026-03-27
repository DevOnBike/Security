#pragma warning disable SYSLIB5001 // <--- DODAJ TO NA SAMEJ G�RZE PLIKU

using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics.Tensors;
using System.Runtime.CompilerServices;

namespace DevOnBike.Heimdall.Somfing
{
    public sealed class FastMatrix : IDisposable
    {
        private readonly double[] _data;
        private readonly int _size;

        public int Cols { get; }
        public int Rows { get; }

        public FastMatrix(int rows, int cols)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(rows);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(cols);

            Rows = rows;
            Cols = cols;

            _size = checked(rows * cols);
            _data = ArrayPool<double>.Shared.Rent(_size);

            _data.AsSpan(0, _size).Clear();
        }

        // Zwracamy 'ref double', co pozwala na odczyt i zapis bez kopiowania
        public ref double this[int row, int col]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get
            {
                return ref _data[row * Cols + col];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Span<double> Row(int row)
        {
            return _data.AsSpan(row * Cols, Cols);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ReadOnlySpan<double> ReadOnlyRow(int row)
        {
            return _data.AsSpan(row * Cols, Cols);
        }

        public ReadOnlySpan<double> AsReadOnlySpan()
        {
            return _data.AsSpan(0, _size);
        }

        public Span<double> AsSpan()
        {
            return _data.AsSpan(0, _size);
        }

        /// <summary>
        /// Eksponuje macierz jako TensorSpan do operacji zapis/odczyt.
        /// Zero alokacji na stercie (zwraca ref struct).
        /// </summary>
        public TensorSpan<double> AsTensor()
        {
            ReadOnlySpan<nint> dimensions = [Rows, Cols];

            return new TensorSpan<double>(AsSpan(), dimensions, default);
        }

        /// <summary>
        /// Eksponuje macierz jako ReadOnlyTensorSpan do bezpiecznych operacji odczytu.
        /// Zero alokacji na stercie.
        /// </summary>
        public ReadOnlyTensorSpan<double> AsReadOnlyTensor()
        {
            ReadOnlySpan<nint> dimensions = [Rows, Cols];

            return new ReadOnlyTensorSpan<double>(AsReadOnlySpan(), dimensions, default);
        }

        public void Clear()
        {
            AsSpan().Clear();
        }

        // =========================
        // SIMD ADD (example op)
        // =========================

        public void Add(FastMatrix other)
        {
            if (other.Rows != Rows || other.Cols != Cols)
            {
                throw new ArgumentException("Shape mismatch");
            }

            TensorPrimitives.Add(AsReadOnlySpan(), other.AsReadOnlySpan(), AsSpan());
        }

        public void Dispose()
        {
            if (_data != null)
            {
                ArrayPool<double>.Shared.Return(_data);
            }

            GC.SuppressFinalize(this);
        }
    }
}