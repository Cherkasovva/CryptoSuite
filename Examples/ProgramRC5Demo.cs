using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Crypto.Context;
using Crypto.Enums;
using Crypto.RC5;

namespace Examples
{
    class ProgramRC5Demo
    {
        public static async Task RunDemo()
        {
            Console.WriteLine("RC5 demo (RC5-32/12) with SymmetricCipherContext tests");

            var rc5 = new RC5Cipher(wordSizeBits: 32, rounds: 12);
            byte[] key = new byte[16]; RandomNumberGenerator.Fill(key);

            rc5.ConfigureRoundKeys(key);

            byte[] block = new byte[rc5.BlockSizeBytes];
            RandomNumberGenerator.Fill(block);
            var enc = rc5.EncryptWithConfiguredKeys(block);
            var dec = rc5.DecryptWithConfiguredKeys(enc);
            Console.WriteLine($"Single-block roundtrip: {block.SequenceEqual(dec)}");


            var ctxECB = new SymmetricCipherContext(rc5, key, CipherModeEnum.ECB, PaddingModeEnum.PKCS7, 
                blockSizeBytes: rc5.BlockSizeBytes);
            var ctxCBC = new SymmetricCipherContext(rc5, key, CipherModeEnum.CBC, PaddingModeEnum.PKCS7, 
                blockSizeBytes: rc5.BlockSizeBytes);
            var ctxCTR = new SymmetricCipherContext(rc5, key, CipherModeEnum.CTR, PaddingModeEnum.PKCS7, 
                blockSizeBytes: rc5.BlockSizeBytes);

            string tmp = Path.Combine(Path.GetTempPath(), "rc5_demo.bin");
            string encf = tmp + ".enc";
            string decf = tmp + ".dec";
            byte[] data = new byte[4096];
            RandomNumberGenerator.Fill(data);
            await File.WriteAllBytesAsync(tmp, data);

            // ECB
            await ctxECB.EncryptFileAsync(tmp, encf);
            await ctxECB.DecryptFileAsync(encf, decf);
            Console.WriteLine("ECB file roundtrip: " + (data.SequenceEqual(await File.ReadAllBytesAsync(decf))));
            File.Delete(encf); File.Delete(decf);

            // CBC
            await ctxCBC.EncryptFileAsync(tmp, encf);
            await ctxCBC.DecryptFileAsync(encf, decf);
            Console.WriteLine("CBC file roundtrip: " + (data.SequenceEqual(await File.ReadAllBytesAsync(decf))));
            File.Delete(encf); File.Delete(decf);

            // CTR
            await ctxCTR.EncryptFileAsync(tmp, encf);
            await ctxCTR.DecryptFileAsync(encf, decf);
            Console.WriteLine("CTR file roundtrip: " + (data.SequenceEqual(await File.ReadAllBytesAsync(decf))));
            File.Delete(encf); File.Delete(decf);

            File.Delete(tmp);

            Console.WriteLine("RC5 demo finished.");
        }
    }
}