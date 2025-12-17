using Crypto.Enums;
using Crypto.Interfaces;
using Crypto.Utils;
using GF256;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Crypto.Context
{
    /// <summary>
    /// Симметричное шифрование
    /// </summary>
    public partial class SymmetricCipherContext
    {
        private readonly ISymmetricCipher cipher; // Алгоритм
        private readonly byte[] masterKey;
        private readonly CipherModeEnum mode; 
        private readonly PaddingModeEnum padding; 
        private readonly int blockSizeBytes; // Размер блока
        private readonly byte[]? iv;  // Вектор инициализации
        private readonly byte[] delta;  // Вектор инициализации

        public SymmetricCipherContext(ISymmetricCipher cipher, byte[] masterKey, CipherModeEnum mode, 
            PaddingModeEnum padding, int blockSizeBytes, byte[]? iv = null)
        {
            this.cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
            this.masterKey = masterKey ?? throw new ArgumentNullException(nameof(masterKey));
            this.mode = mode;
            this.padding = padding;
            if (blockSizeBytes <= 0) throw new ArgumentOutOfRangeException(nameof(blockSizeBytes));
            this.blockSizeBytes = blockSizeBytes;
            this.iv = iv is null ? null : (byte[])iv.Clone();
            cipher.ConfigureRoundKeys(this.masterKey);
            if (mode == CipherModeEnum.RandomDelta)
            {
                delta = new byte[blockSizeBytes];
                using var rng = RandomNumberGenerator.Create(); rng.GetBytes(delta);
            }
            else delta = Array.Empty<byte>();
        }

        /// <summary>
        /// Создаёт или возвращает вектор инициализации
        /// </summary>
        /// <returns></returns>
        private byte[] EnsureIV()
        {
            if (iv != null) 
                return (byte[])iv.Clone();
            var newIv = new byte[blockSizeBytes];
            using var rng = RandomNumberGenerator.Create(); // Объект типа RandomNumberGenerator
            rng.GetBytes(newIv); // Заполнение iv случайными байтами
            return newIv;
        }

        /// <summary>
        /// Асинхронное шифрование
        /// </summary>
        public async Task<byte[]> EncryptAsync(byte[] plaintext, // текст для шифрования
            CancellationToken cancellationToken = default) // токен для отмены операции
        {
            if (plaintext is null) throw new ArgumentNullException(nameof(plaintext));

            // CTR не должен использовать padding 
            if (mode == CipherModeEnum.CTR)
            {
                return await EncryptCTRAsync(plaintext, cancellationToken);
            }

            // Набивка
            byte[] padded = CryptoPadding.ApplyPadding(plaintext, blockSizeBytes, padding);
            switch (mode)
            {
                case CipherModeEnum.ECB: return await EncryptECBAsync(padded, cancellationToken);
                case CipherModeEnum.CBC: return await EncryptCBCAsync(padded, cancellationToken);
                case CipherModeEnum.PCBC: return await EncryptPCBCAsync(padded, cancellationToken);
                case CipherModeEnum.CFB: return await EncryptCFBAsync(padded, cancellationToken);
                case CipherModeEnum.OFB: return await EncryptOFBAsync(padded, cancellationToken);
                case CipherModeEnum.RandomDelta: return await EncryptRandomDeltaAsync(padded, cancellationToken);
                default: throw new NotSupportedException($"Mode {mode} not implemented in this helper.");
            }
        }

        /// <summary>
        /// Асинхронное дешифрование
        /// </summary>
        public async Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default)
        {
            if (ciphertext is null) throw new ArgumentNullException(nameof(ciphertext));
            switch (mode)
            {
                case CipherModeEnum.ECB:
                    {
                        var p = await DecryptECBAsync(ciphertext, cancellationToken);
                        return CryptoPadding.RemovePadding(p, blockSizeBytes, padding);
                    }
                case CipherModeEnum.CBC:
                    {
                        var p = await DecryptCBCAsync(ciphertext, cancellationToken);
                        return CryptoPadding.RemovePadding(p, blockSizeBytes, padding);
                    }
                case CipherModeEnum.CTR:
                    {
                        var p = await DecryptCTRAsync(ciphertext, cancellationToken);
                        return p;
                    }
                case CipherModeEnum.PCBC:
                    {
                        var p = await DecryptPCBCAsync(ciphertext, cancellationToken);
                        return CryptoPadding.RemovePadding(p, blockSizeBytes, padding);
                    }
                case CipherModeEnum.CFB:
                    {
                        var p = await DecryptCFBAsync(ciphertext, cancellationToken);
                        return CryptoPadding.RemovePadding(p, blockSizeBytes, padding);
                    }
                case CipherModeEnum.OFB:
                    {
                        var p = await DecryptOFBAsync(ciphertext, cancellationToken);
                        return CryptoPadding.RemovePadding(p, blockSizeBytes, padding);
                    }
                case CipherModeEnum.RandomDelta:
                    {
                        var p = await DecryptRandomDeltaAsync(ciphertext, cancellationToken);
                        return CryptoPadding.RemovePadding(p, blockSizeBytes, padding);
                    }
                default:
                    throw new NotSupportedException($"Mode {mode} not implemented.");
            }
        }

        /// <summary>
        /// Шифрование.
        /// Реализация ECB (Electronic Codebook) режима с использованием параллельных вычислений.
        /// Каждый блок шифруется независимо. Одинаковые блоки дают одинаковый шифртекст
        /// </summary>
        private Task<byte[]> EncryptECBAsync(byte[] padded, CancellationToken cancellationToken) => Task.Run(() =>
        {
            int blocks = padded.Length / blockSizeBytes; // сколько блоков нужно обработать
            var output = new byte[padded.Length]; // массив для результата (того же размера, что и вход)

            // Parallel.For распределяет блоки между потоками процессора
            Parallel.For(0, blocks, i =>
            {
                var blk = new byte[blockSizeBytes];
                Buffer.BlockCopy(padded, i * blockSizeBytes, blk, 0, blockSizeBytes);
                var enc = cipher.EncryptWithConfiguredKeys(blk);
                Buffer.BlockCopy(enc, 0, output, i * blockSizeBytes, blockSizeBytes);
            });
            return output;
        });

        /// <summary>
        /// Дешифрование.
        /// Реализация ECB (Electronic Codebook) режима
        /// </summary>
        private Task<byte[]> DecryptECBAsync(byte[] cipherText, CancellationToken cancellationToken) => Task.Run(() =>
        {
            int blocks = cipherText.Length / blockSizeBytes;
            var output = new byte[cipherText.Length];
            Parallel.For(0, blocks, i =>
            {
                var blk = new byte[blockSizeBytes];
                Buffer.BlockCopy(cipherText, i * blockSizeBytes, blk, 0, blockSizeBytes);
                var dec = cipher.DecryptWithConfiguredKeys(blk);
                Buffer.BlockCopy(dec, 0, output, i * blockSizeBytes, blockSizeBytes);
            });
            return output;
        });

        /// <summary>
        /// Шифрование.
        /// Реализация CBC (Cipher Block Chaining) режима.
        /// CBC создаёт цепочку блоков, где каждый блок зависит от предыдущего.
        /// Одинаковые блоки дают разный шифртекст.
        /// </summary>
        private async Task<byte[]> EncryptCBCAsync(byte[] padded, CancellationToken cancellationToken)
        {
            byte[] ivLocal = EnsureIV();

            // 1. Берём i-й блок открытого текста
            int blocks = padded.Length / blockSizeBytes;
            var output = new byte[blockSizeBytes + padded.Length];
            Buffer.BlockCopy(ivLocal, 0, output, 0, blockSizeBytes);
            byte[] prev = ivLocal;

            // 2. XOR с предыдущим шифртекстом (или iv для первого блока)
            for (int i = 0; i < blocks; i++)
            {
                int off = i * blockSizeBytes;
                byte[] block = new byte[blockSizeBytes];
                Buffer.BlockCopy(padded, off, block, 0, blockSizeBytes);
                for (int j = 0; j < blockSizeBytes; j++) 
                    block[j] ^= prev[j];
                
                // 3. Шифруем результат XOR
                var enc = cipher.EncryptWithConfiguredKeys(block);
                Buffer.BlockCopy(enc, 0, output, blockSizeBytes + off, blockSizeBytes);
                prev = enc;
            }
            await Task.CompletedTask;
            return output;
        }

        /// <summary>
        /// ДеШифрование.
        /// Реализация CBC (Cipher Block Chaining) режима.
        /// </summary>
        private async Task<byte[]> DecryptCBCAsync(byte[] ciphertextWithIv, CancellationToken cancellationToken)
        {
            if (ciphertextWithIv.Length < blockSizeBytes) throw new InvalidOperationException("Too short");
            byte[] ivLocal = new byte[blockSizeBytes];
            Buffer.BlockCopy(ciphertextWithIv, 0, ivLocal, 0, blockSizeBytes);
            int payloadLen = ciphertextWithIv.Length - blockSizeBytes;
            int blocks = payloadLen / blockSizeBytes;
            var output = new byte[payloadLen];
            byte[] prev = ivLocal;

            for (int i = 0; i < blocks; i++)
            {
                int off = blockSizeBytes + i * blockSizeBytes;
                var cblock = new byte[blockSizeBytes];
                Buffer.BlockCopy(ciphertextWithIv, off, cblock, 0, blockSizeBytes);
                var dec = cipher.DecryptWithConfiguredKeys(cblock);

                for (int j = 0; j < blockSizeBytes; j++) 
                    dec[j] ^= prev[j];
                Buffer.BlockCopy(dec, 0, output, i * blockSizeBytes, blockSizeBytes);
                prev = cblock;
            }
            await Task.CompletedTask;
            return output;
        }

        /// <summary>
        /// Шифрование.
        /// Реализация CTR (Counter) режима.
        /// Поддерживает произвольную длину открытого текста, iv, 
        /// использует счетчик больших порядковых номеров в последних байтах.
        /// Вместо шифрования данных напрямую, CTR шифрует счетчики, а результат XOR'ится с данными.
        /// </summary>
        /// <param name="plaintext"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        private async Task<byte[]> EncryptCTRAsync(byte[] plaintext, CancellationToken cancellationToken)
        {
            byte[] ivLocal = EnsureIV();
            int payloadLen = plaintext.Length;
            int blocks = (payloadLen + blockSizeBytes - 1) / blockSizeBytes; // Округление вверх
            var output = new byte[blockSizeBytes + payloadLen]; 
            Buffer.BlockCopy(ivLocal, 0, output, 0, blockSizeBytes);

            // Массив массивов байтов, чтобы каждый поток мог писать в свой собственный массив
            var results = new byte[blocks][];
            var tasks = new List<Task>(blocks); // Создаём массив задач — по одной задаче на каждый блок

            for (int i = 0; i < blocks; i++)
            {
                int idx = i;
                tasks.Add(Task.Run(() =>
                {
                    // Counter Block — это уникальное значение, которое шифруется для генерации ключевого потока
                    byte[] counterBlock = new byte[blockSizeBytes];

                    Buffer.BlockCopy(ivLocal, // откуда копируем
                        0, // с какого индекса в источнике
                        counterBlock, // куда копируем  
                        0, // с какого индекса в приемнике
                        Math.Min(ivLocal.Length, blockSizeBytes)); // сколько байт копировать
                    long counter = idx;

                    for (int b = 0; b < 8 && b < blockSizeBytes; b++)
                    {
                        // идём с конца
                        counterBlock[blockSizeBytes - 1 - b] = (byte)((counter >> (8 * b)) & 0xFF);
                    }

                    var ks = cipher.EncryptWithConfiguredKeys(counterBlock);

                    // Для неполных блоков
                    int offset = idx * blockSizeBytes; // Вычисление смещения (текущая позиция)

                    // Сколько байт обрабатывать
                    int bytesToProcess = Math.Min(blockSizeBytes, Math.Max(0, payloadLen - offset));
                    var outb = new byte[bytesToProcess];
                    for (int j = 0; j < bytesToProcess; j++)
                        outb[j] = (byte)(plaintext[offset + j] ^ ks[j]);

                    results[idx] = outb;
                }, cancellationToken));
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);

            // Результыт в выходные данные
            for (int i = 0; i < blocks; i++)
            {
                int offset = blockSizeBytes + i * blockSizeBytes;
                Buffer.BlockCopy(results[i], 0, output, offset, results[i].Length);
            }
            return output;
        }

        private async Task<byte[]> DecryptCTRAsync(byte[] ciphertextWithIv, CancellationToken cancellationToken)
        {
            if (ciphertextWithIv.Length < blockSizeBytes) throw new InvalidOperationException("Ciphertext too short to contain IV.");
            byte[] ivLocal = new byte[blockSizeBytes];
            Buffer.BlockCopy(ciphertextWithIv, 0, ivLocal, 0, blockSizeBytes);
            int payloadLen = ciphertextWithIv.Length - blockSizeBytes;
            if (payloadLen < 0) throw new InvalidOperationException("Invalid ciphertext length.");

            int blocks = (payloadLen + blockSizeBytes - 1) / blockSizeBytes;

            // Для итогового открытого текста
            var output = new byte[payloadLen];
            // Для промежуточных результатов (по блокам)
            var results = new byte[blocks][];

            var tasks = new List<Task>(blocks);

            for (int i = 0; i < blocks; i++)
            {
                int idx = i;
                // Вычисляем позицию блока в ciphertextWithIv
                int cOff = blockSizeBytes + idx * blockSizeBytes;

                // Сколько байт нужно обработать в этом блоке
                int bytesAvailable = Math.Min(blockSizeBytes, Math.Max(0, payloadLen - idx * blockSizeBytes));
                var cblock = new byte[bytesAvailable];
                Buffer.BlockCopy(ciphertextWithIv, cOff, cblock, 0, bytesAvailable);

                tasks.Add(Task.Run(() =>
                {
                    byte[] counterBlock = new byte[blockSizeBytes];
                    Buffer.BlockCopy(ivLocal, 0, counterBlock, 0, Math.Min(ivLocal.Length, blockSizeBytes));
                    long counter = idx;
                    for (int b = 0; b < 8 && b < blockSizeBytes; b++)
                    {
                        counterBlock[blockSizeBytes - 1 - b] = (byte)((counter >> (8 * b)) & 0xFF);
                    }

                    var ks = cipher.EncryptWithConfiguredKeys(counterBlock);
                    var plainBlock = new byte[cblock.Length];
                    for (int j = 0; j < cblock.Length; j++) 
                        plainBlock[j] = (byte)(cblock[j] ^ ks[j]); 
                    results[idx] = plainBlock;
                }, cancellationToken));
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);

            for (int i = 0; i < blocks; i++)
            {
                int destOff = i * blockSizeBytes;
                Buffer.BlockCopy(results[i], 0, output, destOff, results[i].Length);
            }
            return output;
        }

        // PCBC (propagating CBC)
        private async Task<byte[]> EncryptPCBCAsync(byte[] padded, CancellationToken cancellationToken)
        {
            byte[] ivLocal = EnsureIV();
            int blocks = padded.Length / blockSizeBytes;
            var output = new byte[blockSizeBytes + padded.Length];
            Buffer.BlockCopy(ivLocal, 0, output, 0, blockSizeBytes);
            var prevCipher = (byte[])ivLocal.Clone();
            var prevPlain = new byte[blockSizeBytes];
            for (int i = 0; i < blocks; i++)
            {
                int off = i * blockSizeBytes;
                var plain = new byte[blockSizeBytes];
                Buffer.BlockCopy(padded, off, plain, 0, blockSizeBytes);
                var x = new byte[blockSizeBytes];
                for (int j = 0; j < blockSizeBytes; j++) 
                    x[j] = (byte)(plain[j] ^ prevCipher[j] ^ prevPlain[j]);
                var enc = cipher.EncryptWithConfiguredKeys(x);
                Buffer.BlockCopy(enc, 0, output, blockSizeBytes + off, blockSizeBytes);
                prevPlain = plain;
                prevCipher = enc;
            }
            await Task.CompletedTask;
            return output;
        }

        private async Task<byte[]> DecryptPCBCAsync(byte[] ciphertextWithIv, CancellationToken cancellationToken)
        {
            if (ciphertextWithIv.Length < blockSizeBytes) throw new InvalidOperationException("Too short");
            byte[] ivLocal = new byte[blockSizeBytes];
            Buffer.BlockCopy(ciphertextWithIv, 0, ivLocal, 0, blockSizeBytes);
            int payloadLen = ciphertextWithIv.Length - blockSizeBytes;
            int blocks = payloadLen / blockSizeBytes;
            var output = new byte[payloadLen];
            var prevCipher = (byte[])ivLocal.Clone();
            var prevPlain = new byte[blockSizeBytes];
            for (int i = 0; i < blocks; i++)
            {
                int off = blockSizeBytes + i * blockSizeBytes;
                var cblock = new byte[blockSizeBytes];
                Buffer.BlockCopy(ciphertextWithIv, off, cblock, 0, blockSizeBytes);
                var dec = cipher.DecryptWithConfiguredKeys(cblock);
                var plain = new byte[blockSizeBytes];
                for (int j = 0; j < blockSizeBytes; j++) 
                    plain[j] = (byte)(dec[j] ^ prevCipher[j] ^ prevPlain[j]);
                Buffer.BlockCopy(plain, 0, output, i * blockSizeBytes, blockSizeBytes);
                prevPlain = plain;
                prevCipher = cblock;
            }
            await Task.CompletedTask;
            return output;
        }

        // CFB (full-block CFB) 
        private async Task<byte[]> EncryptCFBAsync(byte[] padded, CancellationToken cancellationToken)
        {
            byte[] ivLocal = EnsureIV();
            int blocks = padded.Length / blockSizeBytes;
            var output = new byte[blockSizeBytes + padded.Length];
            Buffer.BlockCopy(ivLocal, 0, output, 0, blockSizeBytes);
            var shiftRegister = (byte[])ivLocal.Clone();
            for (int i = 0; i < blocks; i++)
            {
                int off = i * blockSizeBytes;
                var plain = new byte[blockSizeBytes];
                Buffer.BlockCopy(padded, off, plain, 0, blockSizeBytes);
                var encReg = cipher.EncryptWithConfiguredKeys(shiftRegister);
                var cipherBlock = new byte[blockSizeBytes];
                for (int j = 0; j < blockSizeBytes; j++) 
                    cipherBlock[j] = (byte)(encReg[j] ^ plain[j]);
                Buffer.BlockCopy(cipherBlock, 0, output, blockSizeBytes + off, blockSizeBytes);
                // обновить регистр сдвига с помощью шифроблока (полноблочный CFB)
                shiftRegister = cipherBlock;
            }
            await Task.CompletedTask;
            return output;
        }

        private async Task<byte[]> DecryptCFBAsync(byte[] ciphertextWithIv, CancellationToken cancellationToken)
        {
            if (ciphertextWithIv.Length < blockSizeBytes) throw new InvalidOperationException("Too short");
            byte[] ivLocal = new byte[blockSizeBytes];
            Buffer.BlockCopy(ciphertextWithIv, 0, ivLocal, 0, blockSizeBytes);
            int payloadLen = ciphertextWithIv.Length - blockSizeBytes;
            int blocks = payloadLen / blockSizeBytes;
            var output = new byte[payloadLen];
            var shiftRegister = (byte[])ivLocal.Clone();
            for (int i = 0; i < blocks; i++)
            {
                int off = blockSizeBytes + i * blockSizeBytes;
                var cblock = new byte[blockSizeBytes];
                Buffer.BlockCopy(ciphertextWithIv, off, cblock, 0, blockSizeBytes);
                var encReg = cipher.EncryptWithConfiguredKeys(shiftRegister);
                var plain = new byte[blockSizeBytes];
                for (int j = 0; j < blockSizeBytes; j++) 
                    plain[j] = (byte)(encReg[j] ^ cblock[j]);
                Buffer.BlockCopy(plain, 0, output, i * blockSizeBytes, blockSizeBytes);
                shiftRegister = cblock;
            }
            await Task.CompletedTask;
            return output;
        }

        // OFB (Output Feedback)
        private async Task<byte[]> EncryptOFBAsync(byte[] padded, CancellationToken cancellationToken)
        {
            byte[] ivLocal = EnsureIV();
            int blocks = padded.Length / blockSizeBytes;
            var output = new byte[blockSizeBytes + padded.Length];
            Buffer.BlockCopy(ivLocal, 0, output, 0, blockSizeBytes);
            var feedback = (byte[])ivLocal.Clone();
            for (int i = 0; i < blocks; i++)
            {
                int off = i * blockSizeBytes;
                feedback = cipher.EncryptWithConfiguredKeys(feedback);
                var plain = new byte[blockSizeBytes];
                Buffer.BlockCopy(padded, off, plain, 0, blockSizeBytes);
                var cblock = new byte[blockSizeBytes];
                for (int j = 0; j < blockSizeBytes; j++) 
                    cblock[j] = (byte)(plain[j] ^ feedback[j]);
                Buffer.BlockCopy(cblock, 0, output, blockSizeBytes + off, blockSizeBytes);
            }
            await Task.CompletedTask;
            return output;
        }

        private async Task<byte[]> DecryptOFBAsync(byte[] ciphertextWithIv, CancellationToken cancellationToken)
        {
            if (ciphertextWithIv.Length < blockSizeBytes) throw new InvalidOperationException("Too short");
            byte[] ivLocal = new byte[blockSizeBytes];
            Buffer.BlockCopy(ciphertextWithIv, 0, ivLocal, 0, blockSizeBytes);
            int payloadLen = ciphertextWithIv.Length - blockSizeBytes;
            int blocks = payloadLen / blockSizeBytes;
            var output = new byte[payloadLen];
            var feedback = (byte[])ivLocal.Clone();
            for (int i = 0; i < blocks; i++)
            {
                int off = blockSizeBytes + i * blockSizeBytes;
                var cblock = new byte[blockSizeBytes];
                Buffer.BlockCopy(ciphertextWithIv, off, cblock, 0, blockSizeBytes);
                feedback = cipher.EncryptWithConfiguredKeys(feedback);
                var plain = new byte[blockSizeBytes];
                for (int j = 0; j < blockSizeBytes; j++) 
                    plain[j] = (byte)(cblock[j] ^ feedback[j]);
                Buffer.BlockCopy(plain, 0, output, i * blockSizeBytes, blockSizeBytes);
            }
            await Task.CompletedTask;
            return output;
        }

        // RandomDelta (XOR cо случайной delta для каждого блока)
        private async Task<byte[]> EncryptRandomDeltaAsync(byte[] padded, CancellationToken cancellationToken)
        {
            byte[] ivLocal = EnsureIV();
            int blocks = padded.Length / blockSizeBytes;
            var output = new byte[blockSizeBytes + padded.Length]; // префикс iv для совместимости
            Buffer.BlockCopy(ivLocal, 0, output, 0, blockSizeBytes);

            // Дельта уже сохранена в этом файле (или сгенерирована в ctor)
            var deltaLocal = (byte[])delta.Clone();
            var prev = ivLocal;
            for (int i = 0; i < blocks; i++)
            {
                int off = i * blockSizeBytes;
                var plain = new byte[blockSizeBytes];
                Buffer.BlockCopy(padded, off, plain, 0, blockSizeBytes);
                var x = new byte[blockSizeBytes];
                for (int j = 0; j < blockSizeBytes; j++) 
                    x[j] = (byte)(plain[j] ^ deltaLocal[j]);
                var enc = cipher.EncryptWithConfiguredKeys(x);
                Buffer.BlockCopy(enc, 0, output, blockSizeBytes + off, blockSizeBytes);
                // update delta as XOR of enc and prev
                for (int j = 0; j < blockSizeBytes; j++) 
                    deltaLocal[j] = (byte)(deltaLocal[j] ^ enc[j] ^ prev[j]);
                prev = enc;
            }
            await Task.CompletedTask;
            return output;
        }

        private async Task<byte[]> DecryptRandomDeltaAsync(byte[] ciphertextWithIv, CancellationToken cancellationToken)
        {
            if (ciphertextWithIv.Length < blockSizeBytes) throw new InvalidOperationException("Too short");
            byte[] ivLocal = new byte[blockSizeBytes];
            Buffer.BlockCopy(ciphertextWithIv, 0, ivLocal, 0, blockSizeBytes);
            int payloadLen = ciphertextWithIv.Length - blockSizeBytes;
            int blocks = payloadLen / blockSizeBytes;
            var output = new byte[payloadLen];
            var deltaLocal = (byte[])delta.Clone();
            var prev = ivLocal;
            for (int i = 0; i < blocks; i++)
            {
                int off = blockSizeBytes + i * blockSizeBytes;
                var cblock = new byte[blockSizeBytes];
                Buffer.BlockCopy(ciphertextWithIv, off, cblock, 0, blockSizeBytes);
                var dec = cipher.DecryptWithConfiguredKeys(cblock);
                var plain = new byte[blockSizeBytes];
                for (int j = 0; j < blockSizeBytes; j++) 
                    plain[j] = (byte)(dec[j] ^ deltaLocal[j]);
                Buffer.BlockCopy(plain, 0, output, i * blockSizeBytes, blockSizeBytes);
                for (int j = 0; j < blockSizeBytes; j++) 
                    deltaLocal[j] = (byte)(deltaLocal[j] ^ cblock[j] ^ prev[j]);
                prev = cblock;
            }
            await Task.CompletedTask;
            return output;
        }
    }
}