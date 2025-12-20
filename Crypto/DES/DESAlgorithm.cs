using System;
using Utils;

namespace Crypto.DES
{
    internal class DESAlgorithm
    {
        // IP (Initial Permutation) - Начальная перестановка
        // 
        private static readonly int[] IP = {
            58,50,42,34,26,18,10,2,
            60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6,
            64,56,48,40,32,24,16,8,
            57,49,41,33,25,17,9,1,
            59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,
            63,55,47,39,31,23,15,7
        };

        // FP(Final Permutation) - Финальная перестановка
        private static readonly int[] FP = {
            40,8,48,16,56,24,64,32,
            39,7,47,15,55,23,63,31,
            38,6,46,14,54,22,62,30,
            37,5,45,13,53,21,61,29,
            36,4,44,12,52,20,60,28,
            35,3,43,11,51,19,59,27,
            34,2,42,10,50,18,58,26,
            33,1,41,9,49,17,57,25
        };

        private readonly DESRoundFunction roundFunc = new DESRoundFunction();

        /// <summary>
        /// Зашифровать один 8-байтовый блок с помощью предоставленных 16 раундовый ключей (каждый по 6 байт)
        /// </summary>
        /// <param name="block8"></param>
        /// <param name="roundKeys"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] EncryptBlock(byte[] block8, System.Collections.Generic.IReadOnlyList<byte[]> roundKeys)
        {
            if (block8 == null) throw new ArgumentNullException(nameof(block8));
            if (block8.Length != 8) throw new ArgumentException("Block must be 8 bytes");
            if (roundKeys == null || roundKeys.Count != 16) throw new ArgumentException("Round keys: 16 required");

            // начальная перестановка
            var ip = BitPermutor.Permute(block8, IP, bitsIndexedLsbFirst: false, indexStartsAtOne: true);

            // разделить на L и R (по 4 байта в каждом)
            var L = new byte[4];
            var R = new byte[4];
            Buffer.BlockCopy(ip, 0, L, 0, 4);
            Buffer.BlockCopy(ip, 4, R, 0, 4);

            // 16 раундов шифрования
            for (int i = 0; i < 16; i++)
            {
                // Применения F-функции к правой половине
                var F = roundFunc.Transform(R, roundKeys[i]); // 4 bytes
                var newR = new byte[4];
                for (int j = 0; j < 4; j++)
                    // XOR результата с левой половиной
                    newR[j] = (byte)(L[j] ^ F[j]);
                // Смены половин местами: L <- R, R <- newR
                L = R;
                R = newR;
            }

            // финал: объединить R || L (поменять местами)
            var preOut = new byte[8];
            Buffer.BlockCopy(R, 0, preOut, 0, 4);
            Buffer.BlockCopy(L, 0, preOut, 4, 4);

            // финальная перестановка
            var outb = BitPermutor.Permute(preOut, FP, bitsIndexedLsbFirst: false, indexStartsAtOne: true);
            return outb;
        }

        /// <summary>
        /// Дешифрование аналогично шифрованию, но раундовые ключи используются в обратном порядке
        /// </summary>
        public byte[] DecryptBlock(byte[] block8, System.Collections.Generic.IReadOnlyList<byte[]> roundKeys)
        {
            if (block8 == null) throw new ArgumentNullException(nameof(block8));
            if (block8.Length != 8) throw new ArgumentException("Block must be 8 bytes");
            if (roundKeys == null || roundKeys.Count != 16) throw new ArgumentException("Round keys: 16 required");

            var ip = BitPermutor.Permute(block8, IP, bitsIndexedLsbFirst: false, indexStartsAtOne: true);
            var L = new byte[4];
            var R = new byte[4];
            Buffer.BlockCopy(ip, 0, L, 0, 4);
            Buffer.BlockCopy(ip, 4, R, 0, 4);

            for (int i = 15; i >= 0; i--)
            {
                var F = roundFunc.Transform(L, roundKeys[i]); 
                var newL = new byte[4];
                for (int j = 0; j < 4; j++) 
                    newL[j] = (byte)(R[j] ^ F[j]);
                R = L;
                L = newL;
            }

            var preOut = new byte[8];
            Buffer.BlockCopy(L, 0, preOut, 0, 4);
            Buffer.BlockCopy(R, 0, preOut, 4, 4);

            var outb = BitPermutor.Permute(preOut, FP, bitsIndexedLsbFirst: false, indexStartsAtOne: true);
            return outb;
        }
    }
}