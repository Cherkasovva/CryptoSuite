using System;

namespace Crypto.DEAL
{
    /// <summary>
    /// Простая детерминированная генерация 16 подключей по 8 байт из masterKey
    /// </summary>
    internal static class DEALKeySchedule
    {
        // повернуть байт влево на n бит (0..7)
        private static byte Rol(byte b, int n)
        {
            n &= 7;
            return (byte)(((b << n) | (b >> (8 - n))) & 0xFF);
        }

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
                int offset = (i * 7) % mlen;
                for (int j = 0; j < 8; j++)
                {
                    byte b = masterKey[(offset + j) % mlen];
                    // повернуть байт на (i+ j) & 7 и XOR на (i ^ j)
                    b = Rol(b, (i + j) & 7);
                    b ^= (byte)((i * 31 + j * 17) & 0xFF);
                    subs[i][j] = b;
                }
            }
            return subs;
        }
    }
}