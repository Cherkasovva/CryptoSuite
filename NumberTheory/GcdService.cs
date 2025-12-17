using System.Numerics;

namespace NumberTheory
{
    public class GcdService
    {
        /// <summary>
        /// Вычисление НОД двух целых чисел при помощи алгоритма Евклида
        /// </summary>
        public BigInteger Gcd(BigInteger a, BigInteger b) 
        { 
            a = BigInteger.Abs(a); 
            b = BigInteger.Abs(b); 
            while (b != 0) 
            { 
                var r = a % b; 
                a = b; 
                b = r; 
            } 
            return a; 
        }
    }
}