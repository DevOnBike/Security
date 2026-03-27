using System.Diagnostics.CodeAnalysis;
using System.Numerics.Tensors;
using System.Runtime.CompilerServices;

namespace DevOnBike.Security.Tests.Somfing
{
    public readonly struct FastMatrix
    {
        private readonly double[] _data;
        private readonly int _width;
        private readonly int _height;

        public FastMatrix(int width, int height)
        {
            _width = width;
            _height = height;
            _data = new double[width * height];
        }

        // Zwracamy 'ref double', co pozwala na odczyt i zapis bez kopiowania
        public ref double this[int x, int y]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => ref _data[y * _width + x];
        }

        public ReadOnlySpan<double> AsReadOnlySpan()
        {
            return _data;
        }
        
        public Span<double> AsSpan()
        {
            return _data;
        }
        
        /*
        [Experimental("SYSLIB5001")]
        public void ProcessData()
        {
            // Poprawne utworzenie TensorSpan za pomocą konstruktora.
            // Rzutujemy wymiary na nint (IntPtr) i przekazujemy jako ReadOnlySpan<nint>
            var matrix = new TensorSpan<double>(_data, [(nint)_height, (nint)_width]);

            // Operacje są sprzętowo akcelerowane (SIMD) i bez alokacji!
            Tensor.Add(matrix, 5.0, matrix); // Dodaje 5.0 do każdego elementu
        }
        */

    }
}