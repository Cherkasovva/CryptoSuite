using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using Crypto.Utils;
using Crypto.Enums;

namespace Crypto.Context
{
    public partial class SymmetricCipherContext
    {
        // Hазмер буфера для чтения файла. Для простоты он должен быть кратен ublockSizeBytes
        private const int DefaultBufferKb = 64;

        public async Task EncryptFileAsync(string inputPath, string outputPath,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(inputPath)) throw new ArgumentNullException(nameof(inputPath));
            if (string.IsNullOrEmpty(outputPath)) throw new ArgumentNullException(nameof(outputPath));
            if (!File.Exists(inputPath)) throw new FileNotFoundException("input file not found", inputPath);

            bool parallelSafe = (mode == CipherModeEnum.ECB || mode == CipherModeEnum.CTR);
            bool prefixIv = mode != CipherModeEnum.ECB;

            if (parallelSafe)
            {
                await EncryptFileAsync_ParallelSafe(inputPath, outputPath, prefixIv,
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await EncryptFileAsync_Sequential(inputPath, outputPath, prefixIv,
                    cancellationToken).ConfigureAwait(false);
            }
        }

        public async Task EncryptFileAsync_ParallelSafe(string inputPath, string outputPath, bool writeIV, 
            CancellationToken cancellationToken)
        {
            int bufSize = Math.Max(blockSizeBytes, DefaultBufferKb * 1024);
            bufSize = (bufSize / blockSizeBytes) * blockSizeBytes;

            using var fin = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 
                1 << 20, useAsync: true);
            using var fout = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 
                1 << 20, useAsync: true);

            byte[] ivLocal = EnsureIV();
            if (writeIV)
            {
                await fout.WriteAsync(ivLocal, 0, ivLocal.Length, cancellationToken).ConfigureAwait(false);
            }

            var leftover = new List<byte>(blockSizeBytes);
            long ctrCounter = 0;
            bool isCtr = mode == CipherModeEnum.CTR;
            var buffer = new byte[bufSize];

            while (true)
            {
                int read = await fin.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                bool isFinal = fin.Position >= fin.Length;

                int srcPos = 0;
                if (leftover.Count > 0)
                {
                    int need = Math.Min(read, blockSizeBytes - leftover.Count);
                    leftover.AddRange(buffer.Take(need));
                    srcPos += need;
                }

                var accum = new List<byte>();
                if (leftover.Count > 0)
                {
                    accum.AddRange(leftover);
                    leftover.Clear();
                }
                if (read > srcPos)
                {
                    accum.AddRange(buffer.Skip(srcPos).Take(read - srcPos));
                }

                if (isFinal && !isCtr)
                {
                    var padded = CryptoPadding.ApplyPadding(accum.ToArray(), blockSizeBytes, padding);
                    accum = new List<byte>(padded);
                }
                else
                {
                    int full = (accum.Count / blockSizeBytes) * blockSizeBytes;
                    int rem = accum.Count - full;
                    if (rem > 0)
                    {
                        leftover.AddRange(accum.Skip(full).Take(rem));
                        accum.RemoveRange(full, rem);
                    }
                }

                int toProcess = accum.Count;
                if (toProcess > 0)
                {
                    if (mode == CipherModeEnum.ECB)
                    {
                        int blocks = toProcess / blockSizeBytes;
                        var outBuf = new byte[toProcess];
                        var srcBytes = accum.ToArray();
                        Parallel.For(0, blocks, i =>
                        {
                            var srcBlk = new byte[blockSizeBytes];
                            Buffer.BlockCopy(srcBytes, i * blockSizeBytes, srcBlk, 0, blockSizeBytes);
                            var enc = cipher.EncryptWithConfiguredKeys(srcBlk);
                            Buffer.BlockCopy(enc, 0, outBuf, i * blockSizeBytes, blockSizeBytes);
                        });
                        await fout.WriteAsync(outBuf, 0, outBuf.Length, cancellationToken).ConfigureAwait(false);
                    }
                    else if (mode == CipherModeEnum.CTR)
                    {
                        int blocks = toProcess / blockSizeBytes;
                        var outBuf = new byte[toProcess];
                        var srcBytes = accum.ToArray();
                        for (int i = 0; i < blocks; i++)
                        {
                            var plainBlk = new byte[blockSizeBytes];
                            Buffer.BlockCopy(srcBytes, i * blockSizeBytes, plainBlk, 0, blockSizeBytes);
                            var counterBlock = new byte[blockSizeBytes];
                            Buffer.BlockCopy(ivLocal, 0, counterBlock, 0, Math.Min(ivLocal.Length, blockSizeBytes));
                            long c = ctrCounter++;
                            for (int b = 0; b < 8 && b < blockSizeBytes; b++)
                                counterBlock[blockSizeBytes - 1 - b] = (byte)((c >> (8 * b)) & 0xFF);
                            var ks = cipher.EncryptWithConfiguredKeys(counterBlock);
                            for (int j = 0; j < blockSizeBytes; j++) 
                                outBuf[i * blockSizeBytes + j] = (byte)(plainBlk[j] ^ ks[j]);
                        }
                        await fout.WriteAsync(outBuf, 0, outBuf.Length, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        throw new NotSupportedException("ParallelSafe encrypt called for a non-parallel mode.");
                    }
                }

                if (isFinal) break;
            }
        }

        public async Task EncryptFileAsync_Sequential(string inputPath, string outputPath, bool writeIV, 
            CancellationToken cancellationToken)
        {
            int ioBuf = Math.Max(blockSizeBytes, DefaultBufferKb * 1024);
            ioBuf = (ioBuf / blockSizeBytes) * blockSizeBytes;

            using var fin = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 
                1 << 20, useAsync: true);
            using var fout = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 
                1 << 20, useAsync: true);

            byte[] ivLocal = EnsureIV();
            if (writeIV)
            {
                await fout.WriteAsync(ivLocal, 0, ivLocal.Length, cancellationToken).ConfigureAwait(false);
            }

            byte[] prevCipher = ivLocal;
            byte[] prevPlain = new byte[blockSizeBytes];
            var deltaLocal = (byte[])delta.Clone();

            var readBuf = new byte[ioBuf];
            var leftover = new List<byte>(blockSizeBytes);

            while (true)
            {
                int read = await fin.ReadAsync(readBuf, 0, readBuf.Length, cancellationToken).ConfigureAwait(false);
                bool isFinal = fin.Position >= fin.Length;

                int srcPos = 0;
                if (leftover.Count > 0)
                {
                    int need = Math.Min(read, blockSizeBytes - leftover.Count);
                    leftover.AddRange(readBuf.Take(need));
                    srcPos += need;
                }

                var accum = new List<byte>();
                if (leftover.Count > 0)
                {
                    accum.AddRange(leftover);
                    leftover.Clear();
                }
                if (read > srcPos)
                {
                    accum.AddRange(readBuf.Skip(srcPos).Take(read - srcPos));
                }

                if (isFinal)
                {
                    if (mode != CipherModeEnum.CTR)
                    {
                        var padded = CryptoPadding.ApplyPadding(accum.ToArray(), blockSizeBytes, padding);
                        accum = new List<byte>(padded);
                    }
                }
                else
                {
                    int full = (accum.Count / blockSizeBytes) * blockSizeBytes;
                    int rem = accum.Count - full;
                    if (rem > 0)
                    {
                        leftover.AddRange(accum.Skip(full).Take(rem));
                        accum.RemoveRange(full, rem);
                    }
                }

                int toProcess = accum.Count / blockSizeBytes;
                var srcBytes = accum.ToArray();
                var outBuf = new byte[toProcess * blockSizeBytes];
                for (int i = 0; i < toProcess; i++)
                {
                    var plain = new byte[blockSizeBytes];
                    Buffer.BlockCopy(srcBytes, i * blockSizeBytes, plain, 0, blockSizeBytes);
                    byte[] cipherBlock;

                    switch (mode)
                    {
                        case CipherModeEnum.CBC:
                            {
                                var x = new byte[blockSizeBytes];
                                for (int j = 0; j < blockSizeBytes; j++) x[j] = (byte)(plain[j] ^ prevCipher[j]);
                                cipherBlock = cipher.EncryptWithConfiguredKeys(x);
                                prevCipher = cipherBlock;
                                break;
                            }
                        case CipherModeEnum.PCBC:
                            {
                                var x = new byte[blockSizeBytes];
                                for (int j = 0; j < blockSizeBytes; j++) x[j] = 
                                        (byte)(plain[j] ^ prevCipher[j] ^ prevPlain[j]);
                                cipherBlock = cipher.EncryptWithConfiguredKeys(x);
                                prevPlain = plain;
                                prevCipher = cipherBlock;
                                break;
                            }
                        case CipherModeEnum.CFB:
                            {
                                var encReg = cipher.EncryptWithConfiguredKeys(prevCipher);
                                var cblock = new byte[blockSizeBytes];
                                for (int j = 0; j < blockSizeBytes; j++) cblock[j] = (byte)(encReg[j] ^ plain[j]);
                                cipherBlock = cblock;
                                prevCipher = cipherBlock;
                                break;
                            }
                        case CipherModeEnum.OFB:
                            {
                                prevCipher = cipher.EncryptWithConfiguredKeys(prevCipher);
                                var cblock = new byte[blockSizeBytes];
                                for (int j = 0; j < blockSizeBytes; j++) cblock[j] = (byte)(plain[j] ^ prevCipher[j]);
                                cipherBlock = cblock;
                                break;
                            }
                        case CipherModeEnum.RandomDelta:
                            {
                                var x = new byte[blockSizeBytes];
                                for (int j = 0; j < blockSizeBytes; j++) x[j] = (byte)(plain[j] ^ deltaLocal[j]);
                                cipherBlock = cipher.EncryptWithConfiguredKeys(x);
                                for (int j = 0; j < blockSizeBytes; j++) deltaLocal[j] = 
                                        (byte)(deltaLocal[j] ^ cipherBlock[j] ^ prevCipher[j]);
                                prevCipher = cipherBlock;
                                break;
                            }
                        default:
                            throw new NotSupportedException($"Mode {mode} not supported in sequential encrypt path.");
                    }

                    Buffer.BlockCopy(cipherBlock, 0, outBuf, i * blockSizeBytes, blockSizeBytes);
                }

                if (toProcess > 0)
                {
                    await fout.WriteAsync(outBuf, 0, outBuf.Length, cancellationToken).ConfigureAwait(false);
                }

                if (isFinal) break;
            }
        }

        public async Task DecryptFileAsync(string inputPath, string outputPath, 
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(inputPath)) throw new ArgumentNullException(nameof(inputPath));
            if (string.IsNullOrEmpty(outputPath)) throw new ArgumentNullException(nameof(outputPath));
            if (!File.Exists(inputPath)) throw new FileNotFoundException("input file not found", inputPath);

            bool parallelSafe = (mode == CipherModeEnum.ECB || mode == CipherModeEnum.CTR);
            bool prefixIv = mode != CipherModeEnum.ECB;

            if (parallelSafe)
            {
                await DecryptFileAsync_ParallelSafe(inputPath, outputPath, prefixIv, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await DecryptFileAsync_Sequential(inputPath, outputPath, prefixIv, cancellationToken).ConfigureAwait(false);
            }
        }

        public async Task DecryptFileAsync_ParallelSafe(string inputPath, string outputPath, bool readIv, 
            CancellationToken cancellationToken)
        {
            int bufSize = Math.Max(blockSizeBytes, DefaultBufferKb * 1024);
            bufSize = (bufSize / blockSizeBytes) * blockSizeBytes;

            using var fin = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 
                1 << 20, useAsync: true);
            using var fout = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 
                1 << 20, useAsync: true);

            byte[] ivLocal = new byte[blockSizeBytes];
            if (readIv)
            {
                int got = await fin.ReadAsync(ivLocal, 0, ivLocal.Length, cancellationToken).ConfigureAwait(false);
                if (got != ivLocal.Length) throw new InvalidOperationException("Ciphertext too short to contain IV.");
            }
            else
            {
                ivLocal = new byte[blockSizeBytes];
            }

            long ctrCounter = 0;
            var leftover = new List<byte>(blockSizeBytes);
            var buffer = new byte[bufSize];

            while (true)
            {
                int read = await fin.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                bool isFinal = fin.Position >= fin.Length;

                int srcPos = 0;
                if (leftover.Count > 0)
                {
                    int need = Math.Min(read, blockSizeBytes - leftover.Count);
                    leftover.AddRange(buffer.Take(need));
                    srcPos += need;
                }

                var accum = new List<byte>();
                if (leftover.Count > 0)
                {
                    accum.AddRange(leftover);
                    leftover.Clear();
                }
                if (read > srcPos)
                {
                    accum.AddRange(buffer.Skip(srcPos).Take(read - srcPos));
                }

                if (!isFinal)
                {
                    int full = (accum.Count / blockSizeBytes) * blockSizeBytes;
                    int rem = accum.Count - full;
                    if (full >= blockSizeBytes)
                    {
                        int keep = blockSizeBytes;
                        if (full - keep > 0)
                        {
                            var toProcessList = accum.Take(full - keep).ToArray();
                            ctrCounter = await ProcessParallelSafeDecryptionChunk(toProcessList, fout, 
                                ivLocal, ctrCounter, cancellationToken).ConfigureAwait(false);
                        }
                        leftover.AddRange(accum.Skip(full - keep).Take(keep));
                    }
                    else
                    {
                        leftover.AddRange(accum);
                    }
                }
                else
                {
                    if (accum.Count == 0 && leftover.Count == 0) break;

                    if (leftover.Count > 0)
                    {
                        var tmp = leftover.ToArray();
                        var newArr = tmp.Concat(accum).ToArray();
                        accum = new List<byte>(newArr);
                        leftover.Clear();
                    }

                    var all = accum.ToArray();
                    int blocks = all.Length / blockSizeBytes;
                    var plaintextAll = new byte[all.Length];

                    if (mode == CipherModeEnum.ECB)
                    {
                        Parallel.For(0, blocks, i =>
                        {
                            var cblk = new byte[blockSizeBytes];
                            Buffer.BlockCopy(all, i * blockSizeBytes, cblk, 0, blockSizeBytes);
                            var pblk = cipher.DecryptWithConfiguredKeys(cblk);
                            Buffer.BlockCopy(pblk, 0, plaintextAll, i * blockSizeBytes, blockSizeBytes);
                        });
                    }
                    else if (mode == CipherModeEnum.CTR)
                    {
                        for (int i = 0; i < blocks; i++)
                        {
                            var cblk = new byte[blockSizeBytes];
                            Buffer.BlockCopy(all, i * blockSizeBytes, cblk, 0, blockSizeBytes);
                            var counterBlock = new byte[blockSizeBytes];
                            Buffer.BlockCopy(ivLocal, 0, counterBlock, 0, Math.Min(ivLocal.Length, blockSizeBytes));
                            long c = ctrCounter++;
                            for (int b = 0; b < 8 && b < blockSizeBytes; b++)
                                counterBlock[blockSizeBytes - 1 - b] = (byte)((c >> (8 * b)) & 0xFF);
                            var ks = cipher.EncryptWithConfiguredKeys(counterBlock);
                            var pblk = new byte[blockSizeBytes];
                            for (int j = 0; j < blockSizeBytes; j++) pblk[j] = (byte)(cblk[j] ^ ks[j]);
                            Buffer.BlockCopy(pblk, 0, plaintextAll, i * blockSizeBytes, blockSizeBytes);
                        }
                    }

                    var lastBlock = new byte[blockSizeBytes];
                    Buffer.BlockCopy(plaintextAll, (blocks - 1) * blockSizeBytes, lastBlock, 0, blockSizeBytes);
                    var trimmed = CryptoPadding.RemovePadding(lastBlock, blockSizeBytes, padding);

                    if (blocks - 1 > 0)
                    {
                        await fout.WriteAsync(plaintextAll, 0, (blocks - 1) * blockSizeBytes, 
                            cancellationToken).ConfigureAwait(false);
                    }
                    if (trimmed.Length > 0)
                    {
                        await fout.WriteAsync(trimmed, 0, trimmed.Length, cancellationToken).ConfigureAwait(false);
                    }
                    break;
                }
            }
        }

        private async Task<long> ProcessParallelSafeDecryptionChunk(byte[] cipherChunk, FileStream fout, 
            byte[] ivLocal, long ctrCounter, CancellationToken cancellationToken)
        {
            int len = cipherChunk.Length;
            int blocks = len / blockSizeBytes;
            var plainBuf = new byte[len];

            if (mode == CipherModeEnum.ECB)
            {
                Parallel.For(0, blocks, i =>
                {
                    var cblk = new byte[blockSizeBytes];
                    Buffer.BlockCopy(cipherChunk, i * blockSizeBytes, cblk, 0, blockSizeBytes);
                    var pblk = cipher.DecryptWithConfiguredKeys(cblk);
                    Buffer.BlockCopy(pblk, 0, plainBuf, i * blockSizeBytes, blockSizeBytes);
                });
            }
            else if (mode == CipherModeEnum.CTR)
            {
                for (int i = 0; i < blocks; i++)
                {
                    var cblk = new byte[blockSizeBytes];
                    Buffer.BlockCopy(cipherChunk, i * blockSizeBytes, cblk, 0, blockSizeBytes);
                    var counterBlock = new byte[blockSizeBytes];
                    Buffer.BlockCopy(ivLocal, 0, counterBlock, 0, Math.Min(ivLocal.Length, blockSizeBytes));
                    long c = ctrCounter++;
                    for (int b = 0; b < 8 && b < blockSizeBytes; b++)
                        counterBlock[blockSizeBytes - 1 - b] = (byte)((c >> (8 * b)) & 0xFF);
                    var ks = cipher.EncryptWithConfiguredKeys(counterBlock);
                    var pblk = new byte[blockSizeBytes];
                    for (int j = 0; j < blockSizeBytes; j++) pblk[j] = (byte)(cblk[j] ^ ks[j]);
                    Buffer.BlockCopy(pblk, 0, plainBuf, i * blockSizeBytes, blockSizeBytes);
                }
            }
            else throw new NotSupportedException("Invalid parallel-safe mode in helper.");

            await fout.WriteAsync(plainBuf, 0, plainBuf.Length, cancellationToken).ConfigureAwait(false);

            return ctrCounter;
        }

        public async Task DecryptFileAsync_Sequential(string inputPath, string outputPath, bool readIv, 
            CancellationToken cancellationToken)
        {
            int ioBuf = Math.Max(blockSizeBytes, DefaultBufferKb * 1024);
            ioBuf = (ioBuf / blockSizeBytes) * blockSizeBytes;

            using var fin = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 
                1 << 20, useAsync: true);
            using var fout = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 
                1 << 20, useAsync: true);

            byte[] ivLocal = new byte[blockSizeBytes];
            if (readIv)
            {
                int got = await fin.ReadAsync(ivLocal, 0, ivLocal.Length, cancellationToken).ConfigureAwait(false);
                if (got != ivLocal.Length) throw new InvalidOperationException("Ciphertext too short to contain IV.");
            }
            else
            {
                ivLocal = new byte[blockSizeBytes];
            }

            byte[] prevCipher = ivLocal;
            byte[] prevPlain = null;
            var deltaLocal = (byte[])delta.Clone();

            var leftover = new List<byte>(blockSizeBytes);
            var buffer = new byte[ioBuf];

            while (true)
            {
                int read = await fin.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                bool isFinal = fin.Position >= fin.Length;

                int srcPos = 0;
                if (leftover.Count > 0)
                {
                    int need = Math.Min(read, blockSizeBytes - leftover.Count);
                    leftover.AddRange(buffer.Take(need));
                    srcPos += need;
                }

                var accum = new List<byte>();
                if (leftover.Count > 0)
                {
                    accum.AddRange(leftover);
                    leftover.Clear();
                }
                if (read > srcPos)
                {
                    accum.AddRange(buffer.Skip(srcPos).Take(read - srcPos));
                }

                if (!isFinal)
                {
                    int full = (accum.Count / blockSizeBytes) * blockSizeBytes;
                    int rem = accum.Count - full;
                    if (rem > 0)
                    {
                        leftover.AddRange(accum.Skip(full).Take(rem));
                        accum.RemoveRange(full, rem);
                    }
                }
                else
                {
                    if (accum.Count == 0 && leftover.Count == 0) break;
                    if (leftover.Count > 0)
                    {
                        var tmp = leftover.ToArray();
                        var newArr = tmp.Concat(accum).ToArray();
                        accum = new List<byte>(newArr);
                        leftover.Clear();
                    }
                }

                int blocks = accum.Count / blockSizeBytes;
                if (blocks == 0)
                {
                    if (isFinal) { }
                    else continue;
                }

                var srcBytes = accum.ToArray();
                for (int i = 0; i < blocks; i++)
                {
                    var cblk = new byte[blockSizeBytes];
                    Buffer.BlockCopy(srcBytes, i * blockSizeBytes, cblk, 0, blockSizeBytes);
                    byte[] plain;

                    switch (mode)
                    {
                        case CipherModeEnum.CBC:
                            {
                                var dec = cipher.DecryptWithConfiguredKeys(cblk);
                                plain = new byte[blockSizeBytes];
                                for (int j = 0; j < blockSizeBytes; j++) plain[j] = (byte)(dec[j] ^ prevCipher[j]);
                                prevCipher = cblk;
                                break;
                            }
                        case CipherModeEnum.PCBC:
                            {
                                var dec = cipher.DecryptWithConfiguredKeys(cblk);
                                var p = new byte[blockSizeBytes];
                                for (int j = 0; j < blockSizeBytes; j++) p[j] = 
                                        (byte)(dec[j] ^ prevCipher[j] ^ prevPlain?[j] ?? dec[j] ^ prevCipher[j]);
                                prevPlain = p;
                                prevCipher = cblk;
                                plain = p;
                                break;
                            }
                        case CipherModeEnum.CFB:
                            {
                                var encReg = cipher.EncryptWithConfiguredKeys(prevCipher);
                                var p = new byte[blockSizeBytes];
                                for (int j = 0; j < blockSizeBytes; j++) p[j] = (byte)(encReg[j] ^ cblk[j]);
                                prevCipher = cblk;
                                plain = p;
                                break;
                            }
                        case CipherModeEnum.OFB:
                            {
                                prevCipher = cipher.EncryptWithConfiguredKeys(prevCipher);
                                var p = new byte[blockSizeBytes];
                                for (int j = 0; j < blockSizeBytes; j++) p[j] = (byte)(cblk[j] ^ prevCipher[j]);
                                plain = p;
                                break;
                            }
                        case CipherModeEnum.RandomDelta:
                            {
                                var dec = cipher.DecryptWithConfiguredKeys(cblk);
                                var p = new byte[blockSizeBytes];
                                for (int j = 0; j < blockSizeBytes; j++) p[j] = (byte)(dec[j] ^ deltaLocal[j]);
                                for (int j = 0; j < blockSizeBytes; j++) deltaLocal[j] = 
                                        (byte)(deltaLocal[j] ^ cblk[j] ^ prevCipher[j]);
                                prevCipher = cblk;
                                plain = p;
                                break;
                            }
                        default:
                            throw new NotSupportedException($"Mode {mode} not supported in sequential decrypt path.");
                    }

                    if (i == blocks - 1 && !isFinal)
                    {
                        await fout.WriteAsync(plain, 0, plain.Length, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        if (isFinal && i == blocks - 1)
                        {
                            var trimmed = CryptoPadding.RemovePadding(plain, blockSizeBytes, padding);
                            if (trimmed.Length > 0) await fout.WriteAsync(trimmed, 0, trimmed.Length, 
                                cancellationToken).ConfigureAwait(false);
                        }
                        else
                        {
                            await fout.WriteAsync(plain, 0, plain.Length, cancellationToken).ConfigureAwait(false);
                        }
                    }
                }

                if (isFinal) break;
            }
        }
    }
}