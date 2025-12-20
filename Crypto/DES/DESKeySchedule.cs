using System;
using System.Collections.Generic;
using Utils;

namespace Crypto.DES
{
    internal class DESKeySchedule
    {
        // Таблица для начальной перестановки 64-битного ключа
        // Удаляет 8 бит проверки четности (остается 56 бит)
        // Индексы начинаются с 1 
        private static readonly int[] PC1 = {
            57,49,41,33,25,17,9,
            1,58,50,42,34,26,18,
            10,2,59,51,43,35,27,
            19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,
            7,62,54,46,38,30,22,
            14,6,61,53,45,37,29,
            21,13,5,28,20,12,4
        };

        // Для каждого из 16 раундов указывает количество битов для сдвига
        private static readonly int[] Rotations = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        // Сжимающая перестановка из 56 бит в 48 бит
        // Создает раундовый ключ для каждого раунда
        private static readonly int[] PC2 = {
            14,17,11,24,1,5,
            3,28,15,6,21,10,
            23,19,12,4,26,8,
            16,7,27,20,13,2,
            41,52,31,37,47,55,
            30,40,51,45,33,48,
            44,49,39,56,34,53,
            46,42,50,36,29,32
        };


        public IReadOnlyList<byte[]> GenerateRoundKeys(byte[] key64)
        {
            if (key64 == null) throw new ArgumentNullException(nameof(key64));
            if (key64.Length != 8) throw new ArgumentException("DES key must be 8 bytes (64 bits).");

            var pc1 = BitPermutor.Permute(key64, PC1, bitsIndexedLsbFirst: false, indexStartsAtOne: true);
            // 56 bits -> 7 bytes

            // Инициализация половин ключа
            uint c = 0, d = 0;

            // Цикл по первым 28 битам результата PC1
            for (int i = 0; i < 28; i++) 
            {
                int byteIndex = i / 8; // определяет, в каком байте находится бит
                int bitInByte = i % 8; // позиция бита в байте

                // После сдвига у нас все еще целый байт, но нам нужен только младший бит.
                // Поэтому используем &1
                int bit = (pc1[byteIndex] >> (7 - bitInByte)) & 1;

                // Добавляем новый бит в младшую позицию
                c = (c << 1) | (uint)bit; 
            }
            
            for (int i = 0; i < 28; i++)
            {
                int src = 28 + i;
                int byteIndex = src / 8;
                int bitInByte = src % 8;
                int bit = (pc1[byteIndex] >> (7 - bitInByte)) & 1;
                d = (d << 1) | (uint)bit;
            }

            var roundKeys = new List<byte[]>(16);
            for (int round = 0; round < 16; round++)
            {
                int rot = Rotations[round];
                c = BitPermutor.RotateLeftBits(c, 28, rot);
                d = BitPermutor.RotateLeftBits(d, 28, rot);

                byte[] cd = new byte[7];
                for (int i = 0; i < 28; i++)
                {
                    // & 1u - маска (оставляет только младший бит)
                    int bit = (int)((c >> (27 - i)) & 1u);
                    int byteIndex = i / 8;
                    int bitInByte = i % 8;
                    cd[byteIndex] |= (byte)(bit << (7 - bitInByte));
                }
                for (int i = 0; i < 28; i++)
                {
                    int bit = (int)((d >> (27 - i)) & 1u);
                    int pos = 28 + i;
                    int byteIndex = pos / 8;
                    int bitInByte = pos % 8;
                    cd[byteIndex] |= (byte)(bit << (7 - bitInByte));
                }

                var sub = BitPermutor.Permute(cd, PC2, bitsIndexedLsbFirst: false, indexStartsAtOne: true);

                if (sub.Length != 6)
                {
                    var tmp = new byte[6];
                    Buffer.BlockCopy(sub, 0, tmp, 0, Math.Min(sub.Length, 6));
                    sub = tmp;
                }
                roundKeys.Add(sub);
            }
            return roundKeys;
        }
    }
}