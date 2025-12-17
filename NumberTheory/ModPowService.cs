using System;
using System.Numerics;

namespace NumberTheory
{
    public class ModPowService
    {
        /// <summary>
        /// Выполнение операции возведения в степень по модулю
        /// </summary>
        public BigInteger ModPow(BigInteger value, BigInteger exponent, BigInteger modulus)
        {
            if (modulus <= 0) throw new ArgumentOutOfRangeException();
           
            BigInteger baseVal = value % modulus; 
            if (baseVal < 0) 
                baseVal += modulus;

            if (exponent < 0) throw new ArgumentOutOfRangeException("Negative exponent not supported in this simplified ModPow");
            
            BigInteger result = BigInteger.One; // начинаем с 1
            BigInteger exp = exponent;
            while (exp > 0)
            {
                // Если текущий бит = 1 (число нечётное)
                if (!exp.IsEven) 
                    result = (result * baseVal) % modulus;

                // "Отрезаем" младший бит (делим на 2)
                exp >>= 1;

                // Готовим следующую степень двойки
                baseVal = (baseVal * baseVal) % modulus;
            }
            return result;
        }
    }
}