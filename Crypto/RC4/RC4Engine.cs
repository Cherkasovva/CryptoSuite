using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Crypto.RC4
{
    public sealed class RC4Engine
    {
        private readonly byte[] S = new byte[256];
        private int i;
        private int j;

        public RC4Engine(byte[] key)
        {
            if (key == null || key.Length == 0) throw new ArgumentException(nameof(key));
            for (int k = 0; k < 256; k++) 
                S[k] = (byte)k;
            int jLocal = 0;
            for (int k = 0; k < 256; k++)
            {
                jLocal = (jLocal + S[k] + key[k % key.Length]) & 0xFF;
                var tmp = S[k]; S[k] = S[jLocal];
                S[jLocal] = tmp;
            }
            i = 0; j = 0;
        }

        private byte Next()
        {
            i = (i + 1) & 0xFF;
            j = (j + S[i]) & 0xFF;
            var tmp = S[i]; 
            S[i] = S[j]; 
            S[j] = tmp;
            return S[(S[i] + S[j]) & 0xFF];
        }

        public void ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (output.Length < input.Length) throw new ArgumentException("Output too small");
            for (int k = 0; k < input.Length; k++) 
                output[k] = (byte)(input[k] ^ Next());
        }

        public void ProcessBytesInPlace(Span<byte> buffer)
        {
            for (int k = 0; k < buffer.Length; k++) 
                buffer[k] = (byte)(buffer[k] ^ Next());
        }

        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            var eng = new RC4Engine(key);
            var outb = new byte[data.Length];
            eng.ProcessBytes(data, outb);
            return outb;
        }

        public static async Task EncryptFileAsync(byte[] key, string inputPath, string outputPath, 
            int bufferSize = 64 * 1024, CancellationToken cancellationToken = default)
        {
            var eng = new RC4Engine(key);
            using FileStream fin = new FileStream(inputPath, FileMode.Open, FileAccess.Read, 
                FileShare.Read, bufferSize, useAsync: true);
            using FileStream fout = new FileStream(outputPath, FileMode.Create, FileAccess.Write, 
                FileShare.None, bufferSize, useAsync: true);
            byte[] inBuf = new byte[bufferSize]; byte[] outBuf = new byte[bufferSize];
            while (true)
            {
                int read = await fin.ReadAsync(inBuf, 0, inBuf.Length, cancellationToken).ConfigureAwait(false);
                if (read == 0) break;
                eng.ProcessBytes(new ReadOnlySpan<byte>(inBuf, 0, read), new Span<byte>(outBuf, 0, read));
                await fout.WriteAsync(outBuf, 0, read, cancellationToken).ConfigureAwait(false);
            }
        }

        public static Task DecryptFileAsync(byte[] key, string inputPath, string outputPath, 
            int bufferSize = 64 * 1024, CancellationToken cancellationToken = default)
            => EncryptFileAsync(key, inputPath, outputPath, bufferSize, cancellationToken);

        public static byte[] GenerateRandomKey(int length)
        {
            var b = new byte[length]; 
            using var r = RandomNumberGenerator.Create(); 
            r.GetBytes(b); 
            return b;
        }
    }
}