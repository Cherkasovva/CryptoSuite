using System;
using System.Collections.Generic;
using Crypto.Interfaces;

namespace Crypto.RC5
{
    /// <summary>
    /// Реализация блочного шифра RC5
    /// - Размер слова w бит (16/32/64).
    /// - r раундов (обычно 12 или 16).
    /// - Длина ключа b байт (0..255).
    ///
    /// Реализует ISymmetricCipher:
    /// - ConfigureRoundKeys(ключ byte[]) — создает расширенную таблицу S.
    /// - Шифрование/дешифрование (без сохранения состояния; будет создавать круглые ключи для предоставленного ключа)
    /// 
    /// - В RC5 используется строчная интерпретация слов.
    /// - Размер блока = 2 * w бит (2 слова).
    /// </summary>
    public class RC5Cipher : ISymmetricCipher
    {
        private readonly int w; // размер слова в битах
        private readonly int r; 
        private readonly ulong mask; // размер слова в битах
        private readonly int blockSizeBytes;
        private ulong[]? S; // расширенная таблица ключей (t = 2*(r+1))

        // Известные константы
        private static readonly Dictionary<int, (ulong Pw, ulong Qw)> Constants = new Dictionary<int, (ulong, ulong)>()
        {
            {16, (0xB7E1UL, 0x9E37UL)},
            {32, (0xB7E15163UL, 0x9E3779B9UL)},
            {64, (0xB7E151628AED2A6BUL, 0x9E3779B97F4A7C15UL)}
        };

        public RC5Cipher(int wordSizeBits = 32, int rounds = 12)
        {
            if (!(wordSizeBits == 16 || wordSizeBits == 32 || wordSizeBits == 64))
                throw new ArgumentOutOfRangeException(nameof(wordSizeBits), "Supported word sizes: 16, 32, 64 bits.");

            if (rounds <= 0) throw new ArgumentOutOfRangeException(nameof(rounds));

            w = wordSizeBits;
            r = rounds;
            mask = (w == 64) ? ulong.MaxValue : ((1UL << w) - 1);
            blockSizeBytes = (2 * w) / 8;
        }

        public int BlockSizeBytes => blockSizeBytes;

        /// <summary>
        /// Настройка раундовых ключей
        /// </summary>
        public void ConfigureRoundKeys(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            S = KeyExpansion(key);
        }

        /// <summary>
        /// Шифрование без сохранения состояния: расширяет ключ, 
        /// затем шифрует один блок (длина блока открытого текста должна равняться размеру блока).
        /// </summary>
        public byte[] Encrypt(byte[] plaintextBlock, byte[] key)
        {
            if (plaintextBlock == null) throw new ArgumentNullException(nameof(plaintextBlock));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (plaintextBlock.Length != blockSizeBytes) throw new ArgumentException($"Plaintext block must be {blockSizeBytes} bytes.");

            var sLocal = KeyExpansion(key);
            return EncryptBlockWithS(plaintextBlock, sLocal);
        }

        /// <summary>
        /// Расшифровка без сохранения состояния: расширяет ключ, а затем расшифровывает один блок
        /// </summary>
        public byte[] Decrypt(byte[] ciphertextBlock, byte[] key)
        {
            if (ciphertextBlock == null) throw new ArgumentNullException(nameof(ciphertextBlock));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (ciphertextBlock.Length != blockSizeBytes) throw new ArgumentException($"Ciphertext block must be {blockSizeBytes} bytes.");

            var sLocal = KeyExpansion(key);
            return DecryptBlockWithS(ciphertextBlock, sLocal);
        }

        public byte[] EncryptWithConfiguredKeys(byte[] plaintextBlock)
        {
            if (S == null) throw new InvalidOperationException("Round keys not configured.");
            if (plaintextBlock == null) throw new ArgumentNullException(nameof(plaintextBlock));
            if (plaintextBlock.Length != blockSizeBytes) throw new ArgumentException($"Plaintext block must be {blockSizeBytes} bytes.");
            return EncryptBlockWithS(plaintextBlock, S);
        }

        public byte[] DecryptWithConfiguredKeys(byte[] ciphertextBlock)
        {
            if (S == null) throw new InvalidOperationException("Round keys not configured.");
            if (ciphertextBlock == null) throw new ArgumentNullException(nameof(ciphertextBlock));
            if (ciphertextBlock.Length != blockSizeBytes) throw new ArgumentException($"Ciphertext block must be {blockSizeBytes} bytes.");
            return DecryptBlockWithS(ciphertextBlock, S);
        }

        // Key schedule
        private ulong[] KeyExpansion(byte[] K)
        {
            int u = w / 8;                          // байт на слово
            int c = Math.Max(1, (K.Length + u - 1) / u); // количество L слов
            int t = 2 * (r + 1);

            // 1. Преобразует ключевые байты K в слова L[0..c-1], начиная со строчной буквы
            ulong[] L = new ulong[c];
            for (int i = K.Length - 1; i >= 0; i--)
            {
                int idx = i / u;
                L[idx] = ((L[idx] << 8) | K[i]) & mask;
            }

            // 2. Инициализация S
            if (!Constants.TryGetValue(w, out var consts)) throw new InvalidOperationException
                    ("Constants not found for this w.");
            ulong Pw = consts.Pw & mask;
            ulong Qw = consts.Qw & mask;

            ulong[] Slocal = new ulong[t];
            Slocal[0] = Pw;
            for (int i = 1; i < t; i++)
                Slocal[i] = (Slocal[i - 1] + Qw) & mask;

            // 3. Смешать
            int iterations = 3 * Math.Max(t, c);
            ulong A = 0, B = 0;
            int ii = 0, jj = 0;
            for (int k = 0; k < iterations; k++)
            {
                A = Slocal[ii] = RotateLeft((Slocal[ii] + A + B) & mask, 3);
                B = L[jj] = RotateLeft((L[jj] + A + B) & mask, (int)((A + B) & (ulong)(w - 1)));
                ii = (ii + 1) % t;
                jj = (jj + 1) % c;
            }

            return Slocal;
        }

        /// <summary>
        /// Операции с блоками
        /// </summary>
        private byte[] EncryptBlockWithS(byte[] block, ulong[] Slocal)
        {
            // разбить блок на два слова A,B (со строчной буквы)
            ulong A = 0, B = 0;
            int u = w / 8;
            for (int i = 0; i < u; i++) 
                A |= ((ulong)block[i]) << (8 * i);
            for (int i = 0; i < u; i++) 
                B |= ((ulong)block[u + i]) << (8 * i);

            A = (A + Slocal[0]) & mask;
            B = (B + Slocal[1]) & mask;

            for (int i = 1; i <= r; i++)
            {
                A = (RotateLeft((A ^ B) & mask, (int)(B & (ulong)(w - 1))) + Slocal[2 * i]) & mask;
                B = (RotateLeft((B ^ A) & mask, (int)(A & (ulong)(w - 1))) + Slocal[2 * i + 1]) & mask;
            }

            // обратно собрать
            var outb = new byte[blockSizeBytes];
            for (int i = 0; i < u; i++) 
                outb[i] = (byte)((A >> (8 * i)) & 0xFF);
            for (int i = 0; i < u; i++) 
                outb[u + i] = (byte)((B >> (8 * i)) & 0xFF);
            return outb;
        }

        private byte[] DecryptBlockWithS(byte[] block, ulong[] Slocal)
        {
            ulong A = 0, B = 0;
            int u = w / 8;
            for (int i = 0; i < u; i++) 
                A |= ((ulong)block[i]) << (8 * i);
            for (int i = 0; i < u; i++) 
                B |= ((ulong)block[u + i]) << (8 * i);

            for (int i = r; i >= 1; i--)
            {
                B = RotateRight((B - Slocal[2 * i + 1]) & mask, (int)(A & (ulong)(w - 1))) ^ A;
                A = RotateRight((A - Slocal[2 * i]) & mask, (int)(B & (ulong)(w - 1))) ^ B;
            }
            B = (B - Slocal[1]) & mask;
            A = (A - Slocal[0]) & mask;

            var outb = new byte[blockSizeBytes];
            for (int i = 0; i < u; i++) 
                outb[i] = (byte)((A >> (8 * i)) & 0xFF);
            for (int i = 0; i < u; i++) 
                outb[u + i] = (byte)((B >> (8 * i)) & 0xFF);
            return outb;
        }

        private ulong RotateLeft(ulong x, int y)
        {
            y &= (w - 1);
            if (y == 0) 
                return x & mask;
            return (((x << y) | (x >> (w - y))) & mask);
        }

        private ulong RotateRight(ulong x, int y)
        {
            y &= (w - 1);
            if (y == 0) 
                return x & mask;
            return (((x >> y) | (x << (w - y))) & mask);
        }
    }
}