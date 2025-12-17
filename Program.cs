using Crypto.Context;
using Crypto.DEAL;
using Crypto.DES;
using Crypto.DH;
using Crypto.Enums;
using Crypto.RC4;
using Crypto.RC5;
using Crypto.Rijndael;
using Crypto.RSA;
using Crypto.TripleDES;
using GF256;
using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

class Program
{
    static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("=== CryptoSuite — Interactive test harness ===");
        PrintMenu();

        while (true)
        {
            Console.Write("\nSelect option (0 for menu): ");
            var inLine = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(inLine)) continue;
            if (!int.TryParse(inLine.Trim(), out var opt)) { Console.WriteLine("Invalid input."); continue; }

            try
            {
                switch (opt)
                {
                    case 0: PrintMenu(); break;
                    case 1: await TestRC4(); break;
                    case 2: await TestRC5(); break;
                    case 3: await TestRijndaelCBC(); break;
                    case 4: await TestRijndaelCTR(); break;
                    case 5: await TestFeistelSuite(); break;
                    case 6: await TestRSAAndWiener(); break;
                    case 7: await TestDHAndRijndael(); break;
                    case 8: ListGF256Irreducibles(); break;
                    case 9: await RunAllQuick(); break;
                    case 99: Console.WriteLine("Exiting."); return 0;
                    default: Console.WriteLine("Unknown option."); break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: {ex.GetType().Name}: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }
    }

    static void PrintMenu()
    {
        Console.WriteLine();
        Console.WriteLine("1  - RC4 file roundtrip test (async)");
        Console.WriteLine("2  - RC5 tests (single-block + file ECB/CBC/CTR)");
        Console.WriteLine("3  - Rijndael CBC in-memory + file");
        Console.WriteLine("4  - Rijndael CTR in-memory + file");
        Console.WriteLine("5  - DES / TripleDES / DEAL tests");
        Console.WriteLine("6  - RSA keygen + file encrypt/decrypt + Wiener attack check");
        Console.WriteLine("7  - Diffie-Hellman key agreement + Rijndael distribution");
        Console.WriteLine("8  - List GF(2^8) irreducible polynomials");
        Console.WriteLine("9  - Run all quick tests (sequence)");
        Console.WriteLine("99 - Exit");
    }

    // Тестовые методы
    static async Task TestRC4()
    {
        Console.WriteLine("RC4 file roundtrip test");
        var key = RC4Engine.GenerateRandomKey(16);
        string tmp = Path.Combine(Path.GetTempPath(), "rc4_test.bin");
        string enc = tmp + ".enc";
        string dec = tmp + ".dec";
        var data = System.Text.Encoding.UTF8.GetBytes("RC4 test from CryptoSuite\n" + new string('A', 4096));
        await File.WriteAllBytesAsync(tmp, data);
        await RC4Engine.EncryptFileAsync(key, tmp, enc);
        await RC4Engine.DecryptFileAsync(key, enc, dec);
        var orig = await File.ReadAllBytesAsync(tmp);
        var decc = await File.ReadAllBytesAsync(dec);
        Console.WriteLine("RC4 equal: " + orig.SequenceEqual(decc));
        Cleanup(tmp, enc, dec);
    }

    static async Task TestRC5()
    {
        Console.WriteLine("RC5 test (RC5-32/12) — single block + ECB/CBC/CTR file tests");

        var rc5 = new RC5Cipher(wordSizeBits: 32, rounds: 12);
        var key = new byte[16]; RandomNumberGenerator.Fill(key);
        rc5.ConfigureRoundKeys(key);

        // одноблочный текст
        byte[] block = new byte[rc5.BlockSizeBytes];
        RandomNumberGenerator.Fill(block);
        var enc = rc5.EncryptWithConfiguredKeys(block);
        var dec = rc5.DecryptWithConfiguredKeys(enc);
        Console.WriteLine($"Single-block roundtrip: {block.SequenceEqual(dec)}");

        // проверка файлов с помощью SymmetricCipherContext
        var data = new byte[4096]; RandomNumberGenerator.Fill(data);
        string tmp = Path.Combine(Path.GetTempPath(), "rc5_test.bin");
        string encf = tmp + ".enc";
        string decf = tmp + ".dec";
        await File.WriteAllBytesAsync(tmp, data);

        var ctxECB = new SymmetricCipherContext(rc5, key, CipherModeEnum.ECB, PaddingModeEnum.PKCS7, rc5.BlockSizeBytes);
        await ctxECB.EncryptFileAsync(tmp, encf);
        await ctxECB.DecryptFileAsync(encf, decf);
        Console.WriteLine("RC5 ECB file equal: " + data.SequenceEqual(await File.ReadAllBytesAsync(decf)));
        File.Delete(encf); File.Delete(decf);

        var ctxCBC = new SymmetricCipherContext(rc5, key, CipherModeEnum.CBC, PaddingModeEnum.PKCS7, rc5.BlockSizeBytes);
        await ctxCBC.EncryptFileAsync(tmp, encf);
        await ctxCBC.DecryptFileAsync(encf, decf);
        Console.WriteLine("RC5 CBC file equal: " + data.SequenceEqual(await File.ReadAllBytesAsync(decf)));
        File.Delete(encf); File.Delete(decf);

        var ctxCTR = new SymmetricCipherContext(rc5, key, CipherModeEnum.CTR, PaddingModeEnum.PKCS7, rc5.BlockSizeBytes);
        await ctxCTR.EncryptFileAsync(tmp, encf);
        await ctxCTR.DecryptFileAsync(encf, decf);
        Console.WriteLine("RC5 CTR file equal: " + data.SequenceEqual(await File.ReadAllBytesAsync(decf)));
        Cleanup(tmp, encf, decf);
    }

    static async Task TestRijndaelCBC()
    {
        Console.WriteLine("Rijndael CBC test (128/128) in-memory and file");
        IGF256Service gf = new GF256Service();
        byte mod = 0x1B; 
        var rij = new RijndaelCipher(128, 128, gf, mod);
        var key = new byte[16]; RandomNumberGenerator.Fill(key);
        rij.ConfigureRoundKeys(key);
        var ctx = new SymmetricCipherContext(rij, key, CipherModeEnum.CBC, PaddingModeEnum.PKCS7, 16);
        var data = new byte[4096]; RandomNumberGenerator.Fill(data);
        var enc = await ctx.EncryptAsync(data);
        var dec = await ctx.DecryptAsync(enc);
        Console.WriteLine("Rijndael in-memory equal: " + data.SequenceEqual(dec));

        string tmp = Path.Combine(Path.GetTempPath(), "rij_cbc_test.bin");
        string encf = tmp + ".enc";
        string decf = tmp + ".dec";
        await File.WriteAllBytesAsync(tmp, data);
        await ctx.EncryptFileAsync(tmp, encf);
        await ctx.DecryptFileAsync(encf, decf);
        Console.WriteLine("Rijndael CBC file equal: " + (await File.ReadAllBytesAsync(tmp)).SequenceEqual(await File.ReadAllBytesAsync(decf)));
        Cleanup(tmp, encf, decf);
    }

    static async Task TestRijndaelCTR()
    {
        Console.WriteLine("Rijndael CTR test (128/128) in-memory and file");
        IGF256Service gf = new GF256Service();
        byte mod = 0x1B;
        var rij = new RijndaelCipher(128, 128, gf, mod);
        var key = new byte[16]; RandomNumberGenerator.Fill(key);
        rij.ConfigureRoundKeys(key);
        var ctx = new SymmetricCipherContext(rij, key, CipherModeEnum.CTR, PaddingModeEnum.PKCS7, 16);
        var data = new byte[4096]; RandomNumberGenerator.Fill(data);
        var enc = await ctx.EncryptAsync(data);
        var dec = await ctx.DecryptAsync(enc);
        Console.WriteLine("Rijndael CTR in-memory equal: " + data.SequenceEqual(dec));

        string tmp = Path.Combine(Path.GetTempPath(), "rij_ctr_test.bin");
        string encf = tmp + ".enc";
        string decf = tmp + ".dec";
        await File.WriteAllBytesAsync(tmp, data);
        await ctx.EncryptFileAsync(tmp, encf);
        await ctx.DecryptFileAsync(encf, decf);
        Console.WriteLine("Rijndael CTR file equal: " + (await File.ReadAllBytesAsync(tmp)).SequenceEqual(await File.ReadAllBytesAsync(decf)));
        Cleanup(tmp, encf, decf);
    }

    static async Task TestFeistelSuite()
    {
        Console.WriteLine("DES / TripleDES / DEAL tests");

        DebugDESOneBlock();

        // DES single-block
        var des = new DESCipher();
        var desKey = new byte[8]; RandomNumberGenerator.Fill(desKey);
        des.ConfigureRoundKeys(desKey);
        var block = new byte[8]; RandomNumberGenerator.Fill(block);
        var c = des.EncryptWithConfiguredKeys(block);
        var p = des.DecryptWithConfiguredKeys(c);
        Console.WriteLine($"DES roundtrip: {block.SequenceEqual(p)}");

        // TripleDES file test
        var triple = new TripleDESCipher();
        var triKey = new byte[24]; RandomNumberGenerator.Fill(triKey);
        triple.ConfigureRoundKeys(triKey);
        string tmp = Path.Combine(Path.GetTempPath(), "3des_test.bin");
        string enc = tmp + ".enc";
        string dec = tmp + ".dec";
        var data = new byte[32]; RandomNumberGenerator.Fill(data);
        await File.WriteAllBytesAsync(tmp, data);
        var ctx3 = new SymmetricCipherContext(triple, triKey, CipherModeEnum.ECB, PaddingModeEnum.PKCS7, 8);
        await ctx3.EncryptFileAsync(tmp, enc);
        await ctx3.DecryptFileAsync(enc, dec);
        Console.WriteLine("3DES file roundtrip: " + data.SequenceEqual(await File.ReadAllBytesAsync(dec)));
        Cleanup(tmp, enc, dec);

        // DEAL single-block
        var deal = new DEALCipher(16); // ***
        var dealKey = new byte[16]; RandomNumberGenerator.Fill(dealKey);
        deal.ConfigureRoundKeys(dealKey);
        var dealBlock = new byte[16]; RandomNumberGenerator.Fill(dealBlock);
        var encb = deal.EncryptWithConfiguredKeys(dealBlock);
        var decb = deal.DecryptWithConfiguredKeys(encb);
        Console.WriteLine("DEAL roundtrip: " + dealBlock.SequenceEqual(decb));
    }

    static async Task TestRSAAndWiener()
    {
        Console.WriteLine("RSA key generation + file encrypt/decrypt + Wiener attack check (small primes for speed)");
        var keyGen = new RsaService.KeyGenerator(RsaService.PrimalityTestType.MillerRabin, 0.999, primeBitLength: 256);
        var pair = keyGen.GenerateKeyPair(publicExponent: 65537);
        Console.WriteLine($"Generated RSA N bits: {pair.N.GetBitLength()} E: {pair.E}");
        var rsa = new RsaService();
        string tmp = Path.Combine(Path.GetTempPath(), "rsa_test.bin");
        string enc = tmp + ".enc";
        string dec = tmp + ".dec";
        var data = new byte[64]; RandomNumberGenerator.Fill(data);
        await File.WriteAllBytesAsync(tmp, data);
        await rsa.EncryptFileAsync(pair, tmp, enc);
        await rsa.DecryptFileAsync(pair, enc, dec);
        Console.WriteLine("RSA file roundtrip equal: " + (await File.ReadAllBytesAsync(tmp)).SequenceEqual(await File.ReadAllBytesAsync(dec)));

        var wiener = new WienerAttackService();
        var res = wiener.Attack(pair.E, pair.N);
        Console.WriteLine($"Wiener attack success: {res.Success}");
        if (!res.Success)
        {
            Console.WriteLine($"Candidate fractions checked: {res.CandidateFractions.Count}");
        }
        else
        {
            Console.WriteLine($"Recovered d: {res.D}");
        }

        Cleanup(tmp, enc, dec);
    }

    static async Task TestDHAndRijndael()
    {
        Console.WriteLine("Diffie-Hellman demo (small prime for speed) and Rijndael key distribution");
        var nt = new NumberTheory.StatelessNumberTheoryService();
        var mr = new Primality.MillerRabinPrimalityTest(nt, RandomNumberGenerator.Create());
        BigInteger p;
        var rng = RandomNumberGenerator.Create();
        int bits = 512;
        while (true)
        {
            byte[] buf = new byte[(bits + 7) / 8];
            rng.GetBytes(buf);
            buf[buf.Length - 1] |= (byte)(1 << ((bits - 1) % 8));
            buf[0] |= 1;
            p = new BigInteger(buf.Concat(new byte[] { 0 }).ToArray());
            if (p < 0) p = BigInteger.Negate(p);
            if (mr.IsProbablyPrime(p, 0.999)) break;
        }

        var dh = new DiffieHellmanService(p, new BigInteger(2), rng);
        var (aPriv, aPub) = dh.GenerateKeyPair();
        var (bPriv, bPub) = dh.GenerateKeyPair();
        var aShared = dh.ComputeSharedSecret(aPriv, bPub);
        var bShared = dh.ComputeSharedSecret(bPriv, aPub);
        Console.WriteLine("Shared secrets equal: " + (aShared == bShared));
        var keyBytes = DiffieHellmanService.DeriveAesKey(aShared, 16);

        IGF256Service gf = new GF256Service();
        var rij = new RijndaelCipher(128, 128, gf, 0x1B);
        rij.ConfigureRoundKeys(keyBytes);
        var ctx = new SymmetricCipherContext(rij, keyBytes, CipherModeEnum.CBC, PaddingModeEnum.PKCS7, 16);
        var data = new byte[1024]; rng.GetBytes(data);
        var enc = await ctx.EncryptAsync(data);
        var dec = await ctx.DecryptAsync(enc);
        Console.WriteLine("Rijndael via DH derived key roundtrip equal: " + data.SequenceEqual(dec));
    }

    static void DebugDESOneBlock()
    {
        var des = new Crypto.DES.DESCipher();
        var desKey = new byte[8];
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        rng.GetBytes(desKey);
        des.ConfigureRoundKeys(desKey);

        byte[] block = new byte[8];
        rng.GetBytes(block);

        //Console.WriteLine("Plain:  " + Crypto.DES.DESCipher.ToHex(block));

        //var encDbg = des.EncryptWithConfiguredKeysDebug(block);
        //Console.WriteLine("IP(plain):    " + Crypto.DES.DESCipher.ToHex(encDbg.ipPlain));
        //Console.WriteLine("Mid (enc):    " + Crypto.DES.DESCipher.ToHex(encDbg.midEncrypt));
        //Console.WriteLine("Cipher:       " + Crypto.DES.DESCipher.ToHex(encDbg.cipher));

        //var decDbg = des.DecryptWithConfiguredKeysDebug(encDbg.cipher);
        //Console.WriteLine("IP(cipher):   " + Crypto.DES.DESCipher.ToHex(decDbg.ipCipher));
        //Console.WriteLine("Mid (dec):    " + Crypto.DES.DESCipher.ToHex(decDbg.midDecrypt));
        //Console.WriteLine("Plain (dec):  " + Crypto.DES.DESCipher.ToHex(decDbg.plain));

        //Console.WriteLine();
        //Console.WriteLine("Checks:");
        //Console.WriteLine("IP(cipher) == Mid(enc) ? " + (Crypto.DES.DESCipher.ToHex(decDbg.ipCipher) == 
        //    Crypto.DES.DESCipher.ToHex(encDbg.midEncrypt)));
        //Console.WriteLine("Mid(dec) == IP(plain) ? " + (Crypto.DES.DESCipher.ToHex(decDbg.midDecrypt) == 
        //    Crypto.DES.DESCipher.ToHex(encDbg.ipPlain)));
        //Console.WriteLine("Plain == Plain(dec) ? " + (Crypto.DES.DESCipher.ToHex(block) == 
        //    Crypto.DES.DESCipher.ToHex(decDbg.plain)));
    }

    static void ListGF256Irreducibles()
    {
        IGF256Service gf = new GF256Service();
        var irr = gf.GetAllIrreducibleDegree8();
        Console.WriteLine($"Found {irr.Length} irreducible polynomials of degree 8:");
        Console.WriteLine(string.Join(", ", irr.Select(b => $"0x{b:X2}")));
    }

    static async Task RunAllQuick()
    {
        Console.WriteLine("Running all quick tests sequentially (may take a while)...");
        await TestRC4();
        await TestRC5();
        await TestRijndaelCBC();
        await TestRijndaelCTR();
        await TestFeistelSuite();
        await TestRSAAndWiener();
        await TestDHAndRijndael();
        ListGF256Irreducibles();
        Console.WriteLine("All quick tests finished.");
    }

    static void Cleanup(params string[] files)
    {
        foreach (var f in files)
        {
            try { if (File.Exists(f)) File.Delete(f); } catch { }
        }
    }
}

static class BigIntExtensions
{
    public static int GetBitLength(this BigInteger v)
    {
        if (v.IsZero) return 0;
        BigInteger t = v < 0 ? BigInteger.Negate(v) : v;
        int bits = 0;
        while (t > 0) 
        { 
            bits++; 
            t >>= 1; 
        }
        return bits;
    }
}