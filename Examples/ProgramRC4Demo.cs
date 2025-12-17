using Crypto.RC4;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Examples
{
    class ProgramRC4Demo
    {
        public static async Task RunDemo()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("RC4 demo: async file encryption/decryption\n");

            byte[] key = RC4Engine.GenerateRandomKey(16);
            Console.WriteLine($"Generated RC4 key ({key.Length} bytes)");

            string tmpDir = Path.Combine(Path.GetTempPath(), "rc4_demo");
            Directory.CreateDirectory(tmpDir);
            string inputPath = Path.Combine(tmpDir, "input.bin");
            string encryptedPath = Path.Combine(tmpDir, "input.bin.enc");
            string decryptedPath = Path.Combine(tmpDir, "input.bin.dec");

            byte[] text = Encoding.UTF8.GetBytes("This is a small demo file for RC4 encryption.\n");
            byte[] random = new byte[1024 * 16];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(random);
            using (var fs = new FileStream(inputPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await fs.WriteAsync(text, 0, text.Length);
                await fs.WriteAsync(random, 0, random.Length);
            }

            try
            {
                Console.WriteLine($"Encrypting {inputPath} -> {encryptedPath} ...");
                await RC4Engine.EncryptFileAsync(key, inputPath, encryptedPath);
                Console.WriteLine("Encryption completed.");

                Console.WriteLine($"Decrypting {encryptedPath} -> {decryptedPath} ...");
                await RC4Engine.DecryptFileAsync(key, encryptedPath, decryptedPath);
                Console.WriteLine("Decryption completed.");

                byte[] orig = await File.ReadAllBytesAsync(inputPath);
                byte[] dec = await File.ReadAllBytesAsync(decryptedPath);
                bool eq = orig.Length == dec.Length;
                if (eq)
                {
                    for (int i = 0; i < orig.Length; i++) if (orig[i] != dec[i]) { eq = false; break; }
                }
                Console.WriteLine($"Roundtrip equality: {eq}");
            }
            finally
            {
                try { File.Delete(inputPath); } catch { }
                try { File.Delete(encryptedPath); } catch { }
                try { File.Delete(decryptedPath); } catch { }
                try { Directory.Delete(tmpDir); } catch { }
            }
        }
    }
}