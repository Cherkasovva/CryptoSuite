using Crypto.Rijndael;
using GF256;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Examples
{
    class ProgramRijndaelDemo
    {
        public static async Task RunDemo()
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.WriteLine("Rijndael demo");

            IGF256Service gf = new GF256Service();
            byte gfMod = 0x1B; 

            int blockBits = 128, keyBits = 128;
            var cipher = new RijndaelCipher(blockBits, keyBits, gf, gfMod);

            byte[] key = new byte[16]; for (int i = 0; i < 16; i++) key[i] = (byte)i;
            byte[] block = new byte[16]; for (int i = 0; i < 16; i++) block[i] = (byte)(i * 3);

            cipher.ConfigureRoundKeys(key);
            var encrypted = cipher.EncryptWithConfiguredKeys(block);
            var decrypted = cipher.DecryptWithConfiguredKeys(encrypted);
            Console.WriteLine($"Equal: {decrypted.SequenceEqual(block)}");

            string tmp = Path.Combine(Path.GetTempPath(), "rij_demo.bin");
            string enc = tmp + ".enc";
            string dec = tmp + ".dec";
            try
            {
                await File.WriteAllBytesAsync(tmp, block);
                var ctx = new Crypto.Context.SymmetricCipherContext(cipher, key, 
                    Crypto.Enums.CipherModeEnum.CBC, Crypto.Enums.PaddingModeEnum.PKCS7, blockSizeBytes: blockBits / 8);
                await ctx.EncryptFileAsync(tmp, enc);
                await ctx.DecryptFileAsync(enc, dec);
                var orig = await File.ReadAllBytesAsync(tmp);
                var decb = await File.ReadAllBytesAsync(dec);
                Console.WriteLine($"File roundtrip equal: {orig.SequenceEqual(decb)}");
            }
            finally
            {
                try { File.Delete(tmp); } catch { }
                try { File.Delete(enc); } catch { }
                try { File.Delete(dec); } catch { }
            }
        }
    }
}