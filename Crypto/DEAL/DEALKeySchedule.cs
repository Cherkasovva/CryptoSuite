using System;

namespace Crypto.DEAL
{
    /// <summary>
    /// Простая детерминированная генерация 16 подключей по 8 байт из masterKey
    /// </summary>
    internal static class DEALKeySchedule
    {
        // Метод циклического сдвига байта: повернуть байт влево на n бит (0..7)
        private static byte Rol(byte b, int n)
        {
            // Ограничение сдвига диапазоном 0-7
            n &= 7;
            return (byte)(((b << n) | (b >> (8 - n))) & 0xFF);
            // & 0xFF: маска для получения только младших 8 бит
        }

        /// <summary>
        /// Основной метод генерации подключей
        /// </summary>
        public static byte[][] GenerateSubKeys(byte[] masterKey)
        {
            if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));
            if (masterKey.Length == 0) throw new ArgumentException("masterKey must not be empty");

            // создать 16 subkeys, каждый по 8 байтов
            var subs = new byte[16][];
            int mlen = masterKey.Length;
            for (int i = 0; i < 16; i++)
            {
                subs[i] = new byte[8];
                // Вычисление начального смещения в мастер-ключе
                int offset = (i * 7) % mlen;
                for (int j = 0; j < 8; j++)
                {
                    // 1. Берем байт из мастер-ключа
                    byte b = masterKey[(offset + j) % mlen];
                    // 2. Циклически сдвигаем байт влево на (i+ j) & 7
                    b = Rol(b, (i + j) & 7);
                    // 3. Применяем XOR с константой
                    b ^= (byte)((i * 31 + j * 17) & 0xFF);
                    subs[i][j] = b;
                }
            }
            return subs;
        }
    }
}