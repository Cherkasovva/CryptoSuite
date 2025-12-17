using System.Numerics;

namespace NumberTheory
{
    public class ExtendedGcdService
    {
        /// <summary>
        /// Вычисление НОД двух целых чисел и решения соотношения Безу a·x + b·y = НОД(a, b)
        /// при помощи расширенного алгоритма Евклида
        /// </summary>
        public (BigInteger gcd, BigInteger x, BigInteger y) 
            ExtendedGcd(BigInteger a, BigInteger b)
        {
            BigInteger aa = a, bb = b;
            BigInteger x0 = 1, x1 = 0, y0 = 0, y1 = 1; // коэффициента для а и b
            while (bb != 0)
            {
                var q = aa / bb; 
                var r = aa % bb; 
                aa = bb; bb = r;
                var nx = x0 - q * x1; 
                x0 = x1; 
                x1 = nx;
                var ny = y0 - q * y1; 
                y0 = y1; 
                y1 = ny;
            }
            return (aa, x0, y0);
        }
    }
}