using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Linq;

namespace Primality
{
    /// <summary>
    /// Реализация криптографически безопасной генерации случайных больших целых чисел
    /// </summary>
    internal static class RandomBigInteger
    {
        public static BigInteger GetRandomBigIntegerBelow(BigInteger max, // верхняя граница 
            RandomNumberGenerator rng) // криптографически безопасный генератор случайных чисел
        {
            if (max <= 0) throw new ArgumentOutOfRangeException();

            // Вычисление необходимого количества байтов
            int bytes = (int)Math.Ceiling((double)GetBitLength(max) / 8.0);
            byte[] buffer = new byte[bytes]; // создание буфера и генерация байтов
            while (true)
            {
                rng.GetBytes(buffer);

                // Добавляем нулевой байт
                // Гарантируем, что старший бит = 0 -> число неотрицательное 
                var candidate = new BigInteger(buffer.Concat(new byte[] { 0 }).ToArray());
                if (candidate < 0) 
                    candidate = BigInteger.Negate(candidate);
                if (candidate < max) 
                    return candidate;
            }
        }

        /// <summary>
        /// Длина по битами
        /// </summary>
        private static int GetBitLength(BigInteger value)
        {
            if (value.IsZero) 
                return 0;

            // Получение абсолютного значения
            BigInteger v = value < 0 ? BigInteger.Negate(value) : value;
            int bits = 0;

            // Подсчет битов
            while (v > 0) 
            { 
                bits++; 
                v >>= 1; 
            } 
            return bits;
        }
    }
}