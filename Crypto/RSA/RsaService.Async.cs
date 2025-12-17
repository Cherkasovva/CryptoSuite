using System;
using System.IO;
using System.Numerics;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Linq;

namespace Crypto.RSA
{
    /// <summary>
    /// RSA в режиме блочного шифрования:
    /// RSA может шифровать блоки данных размера <= размера модуля. 
    /// Для файлов: разбиваем на блоки, шифруем каждый, объединяем.
    /// Размер модуля RSA(k) определяет максимальный размер блока
    /// </summary>
    public partial class RsaService
    {
        public async Task EncryptFileAsync(RsaKeyPair key, string inputPath, string outputPath, 
            CancellationToken cancellationToken = default)
        {
            if (key is null) throw new ArgumentNullException(nameof(key));
            if (string.IsNullOrEmpty(inputPath)) throw new ArgumentNullException(nameof(inputPath));
            if (string.IsNullOrEmpty(outputPath)) throw new ArgumentNullException(nameof(outputPath));

            // Расчет размера модуля (в байтах)
            long kLong = (long)(key.N.GetBitLength() + 7) / 8;
            if (kLong > int.MaxValue) throw new InvalidOperationException("Modulus too large.");
            int k = (int)kLong;

            // Минимальный размер: 11 байт, иначе не поместится набивка
            if (k < 11) throw new ArgumentException("Modulus too small for PKCS#1 v1.5.");

            int maxData = k - 11;

            using var fin = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 
                1 << 20, useAsync: true); // 1 << 20 - размер буфера
            using var fout = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 
                1 << 20, useAsync: true);

            // Чтение и разбиение файла на блоки
            var blocks = new List<byte[]>();
            while (true)
            {
                var buf = new byte[maxData];
                int r = await fin.ReadAsync(buf, 0, buf.Length, cancellationToken).ConfigureAwait(false);
                if (r == 0) 
                    break; // конец файла
                var b = new byte[r];
                Buffer.BlockCopy(buf, 0, b, 0, r);
                blocks.Add(b);
            }

            // Параллельное шифрование блоков
            var results = new byte[blocks.Count][];
            await Task.Run(() =>
            {
                Parallel.For(0, blocks.Count, i =>
                {
                    var block = blocks[i];
                    // Создание массива для данных набивки
                    byte[] padded = new byte[k];

                    //Заголовок PKCS#1 
                    padded[0] = 0x00; // всегда (обеспечает, что число < модуля N)
                    padded[1] = 0x02; // означает "шифрование данных"
                    int psLen = k - 3 - block.Length;
                    if (psLen < 8) throw new InvalidOperationException("Message too long for RSA modulus");

                    // Создание локального RNG, каждый поток получает свой собственный RNG
                    using var rng = RandomNumberGenerator.Create();

                    // Создание буфера для PS
                    var ps = new byte[psLen];
                    // Генерация ненулевых случайных байтов
                    while (true)
                    {
                        rng.GetBytes(ps);
                        bool hasZero = false;
                        for (int j = 0; j < psLen; j++) 
                            if (ps[j] == 0) 
                            { 
                                hasZero = true; 
                                break; 
                            }
                        if (!hasZero) 
                            break;
                    }

                    // Копирование PS в padded блок
                    Buffer.BlockCopy(ps, 0, padded, 2, psLen); 
                    padded[2 + psLen] = 0x00; // разделитель
                    // Копирование оригинальных данных
                    Buffer.BlockCopy(block, 0, padded, 3 + psLen, block.Length);

                    var m = new BigInteger(padded.Concat(new byte[] { 0 }).ToArray());
                    if (m < 0) 
                        m = BigInteger.Negate(m);

                    // RSA шифрование: c = m^e mod n
                    var c = modPow.ModPow(m, key.E, key.N);
                    var cb = c.ToByteArray(isUnsigned: true, isBigEndian: true);

                    // Дополнение нулями слева
                    if (cb.Length < k)
                    {
                        var tmp = new byte[k];
                        Buffer.BlockCopy(cb, 0, tmp, k - cb.Length, cb.Length);
                        cb = tmp;
                    }
                    results[i] = cb;
                });
            }).ConfigureAwait(false);

            for (int i = 0; i < results.Length; i++)
            {
                // Последовательная запись блоков
                await fout.WriteAsync(results[i], 0, results[i].Length, cancellationToken).ConfigureAwait(false);
            }
        }

        public async Task DecryptFileAsync(RsaKeyPair key, string inputPath, string outputPath, 
            CancellationToken cancellationToken = default)
        {
            if (key is null) throw new ArgumentNullException(nameof(key));
            if (string.IsNullOrEmpty(inputPath)) throw new ArgumentNullException(nameof(inputPath));
            if (string.IsNullOrEmpty(outputPath)) throw new ArgumentNullException(nameof(outputPath));

            long kLong = (long)(key.N.GetBitLength() + 7) / 8;
            if (kLong > int.MaxValue) throw new InvalidOperationException("Modulus too large.");
            int k = (int)kLong;

            using var fin = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 
                1 << 20, useAsync: true);
            using var fout = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 
                1 << 20, useAsync: true);

            // Расчет количества блоков в файле
            long totalLong = fin.Length / kLong;
            if (totalLong > int.MaxValue) throw new InvalidOperationException("File too large to process in this routine.");
            int total = (int)totalLong;

            var list = new List<byte[]>();
            for (int i = 0; i < total; i++)
            {
                var buf = new byte[k];
                int r = await fin.ReadAsync(buf, 0, buf.Length, cancellationToken).ConfigureAwait(false);
                if (r != k) throw new InvalidOperationException("Unexpected read length during RSA block processing.");
                list.Add(buf);
            }

            var results = new byte[list.Count][];
            await Task.Run(() =>
            {
                Parallel.For(0, list.Count, i =>
                {
                    var cb = list[i];
                    var c = new BigInteger(cb.Concat(new byte[] { 0 }).ToArray());
                    if (c < 0) 
                        c = BigInteger.Negate(c);
                    var m = modPow.ModPow(c, key.D, key.N);
                    var mb = m.ToByteArray(isUnsigned: true, isBigEndian: true);
                    if (mb.Length < k)
                    {
                        var tmp = new byte[k];
                        Buffer.BlockCopy(mb, 0, tmp, k - mb.Length, mb.Length);
                        mb = tmp;
                    }
                    // Удаление разделителя 0x00
                    int idx = 2; 
                    while (idx < mb.Length && mb[idx] != 0) 
                        idx++; 
                    int dataStart = idx + 1; // индекс первого байта оригинальных данных (после разделителя)
                    if (dataStart < 0 || dataStart > mb.Length) results[i] = Array.Empty<byte>();
                    else
                    {
                        var data = new byte[mb.Length - dataStart];
                        Buffer.BlockCopy(mb, dataStart, data, 0, data.Length);
                        results[i] = data;
                    }
                });
            }).ConfigureAwait(false);

            for (int i = 0; i < results.Length; i++)
            {
                await fout.WriteAsync(results[i], 0, results[i].Length, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}