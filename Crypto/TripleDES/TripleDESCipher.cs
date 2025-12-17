using System;
using Crypto.Interfaces;
using Crypto.DES;

namespace Crypto.TripleDES
{
    /// <summary>
    /// TripleDES (EDE) реализован с использованием реализации project DES.
    /// Поддерживает варианты с 2 ключами (16 байт) и 3 ключами (24 байта).
    /// Предусмотрены одноблочные операции (шифрование/дешифрование без учета состояния и варианты с настроенным ключом).
    /// Режимы более высокого уровня (ECB/CBC/CFB/OFB/CTR/PCBC/RandomDelta) обрабатываются SymmetricCipherContext.
    /// </summary>
    public class TripleDESCipher : ISymmetricCipher, IDisposable
    {
        private DESCipher? des1;
        private DESCipher? des2;
        private DESCipher? des3;
        private bool configured = false;
        private bool twoKey = false;

        public int BlockSizeBytes => 8;

        public TripleDESCipher()
        {
        }

        /// <summary>
        /// Настройте раундовые ключи из 16- или 24-байтового ключа.
        /// 16 байт -> K1, K2, K3 = K1 
        /// 24 байта -> K1, K2, K3 
        /// </summary>
        public void ConfigureRoundKeys(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != 16 && key.Length != 24) throw new ArgumentException("TripleDES key must be 16 (two-key) or 24 (three-key) bytes long.");

            DisposeInternal();

            byte[] k1 = new byte[8];
            byte[] k2 = new byte[8];
            byte[] k3 = new byte[8];

            Buffer.BlockCopy(key, 0, k1, 0, 8);
            Buffer.BlockCopy(key, 8, k2, 0, 8);
            if (key.Length == 24)
            {
                Buffer.BlockCopy(key, 16, k3, 0, 8);
                twoKey = false;
            }
            else
            {
                // 16-byte key -> k3 = k1
                Buffer.BlockCopy(k1, 0, k3, 0, 8);
                twoKey = true;
            }

            des1 = new DESCipher();
            des2 = new DESCipher();
            des3 = new DESCipher();
            des1.ConfigureRoundKeys(k1);
            des2.ConfigureRoundKeys(k2);
            des3.ConfigureRoundKeys(k3);
            configured = true;
        }

        public byte[] Encrypt(byte[] plaintextBlock, byte[] key)
        {
            if (plaintextBlock == null) throw new ArgumentNullException(nameof(plaintextBlock));
            if (plaintextBlock.Length != BlockSizeBytes) throw new ArgumentException($"Plaintext block must be {BlockSizeBytes} bytes.");
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != 16 && key.Length != 24) throw new ArgumentException("TripleDES key must be 16 or 24 bytes long.");

            byte[] k1 = new byte[8];
            byte[] k2 = new byte[8];
            byte[] k3 = new byte[8];
            Buffer.BlockCopy(key, 0, k1, 0, 8);
            Buffer.BlockCopy(key, 8, k2, 0, 8);
            if (key.Length == 24)
            {
                Buffer.BlockCopy(key, 16, k3, 0, 8);
            }
            else
            {
                Buffer.BlockCopy(k1, 0, k3, 0, 8); 
            }

            var d = new DESCipher();
            var t1 = d.Encrypt(plaintextBlock, k1);
            var t2 = d.Decrypt(t1, k2);
            var t3 = d.Encrypt(t2, k3);
            return t3;
        }

        public byte[] Decrypt(byte[] ciphertextBlock, byte[] key)
        {
            if (ciphertextBlock == null) throw new ArgumentNullException(nameof(ciphertextBlock));
            if (ciphertextBlock.Length != BlockSizeBytes) throw new ArgumentException
                    ($"Ciphertext block must be {BlockSizeBytes} bytes.");
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != 16 && key.Length != 24) throw new ArgumentException
                    ("TripleDES key must be 16 or 24 bytes long.");

            byte[] k1 = new byte[8];
            byte[] k2 = new byte[8];
            byte[] k3 = new byte[8];
            Buffer.BlockCopy(key, 0, k1, 0, 8);
            Buffer.BlockCopy(key, 8, k2, 0, 8);
            if (key.Length == 24)
            {
                Buffer.BlockCopy(key, 16, k3, 0, 8);
            }
            else
            {
                Buffer.BlockCopy(k1, 0, k3, 0, 8);
            }

            var d = new DESCipher();
            var t1 = d.Decrypt(ciphertextBlock, k3);
            var t2 = d.Encrypt(t1, k2);
            var t3 = d.Decrypt(t2, k1);
            return t3;
        }

        public byte[] EncryptWithConfiguredKeys(byte[] plaintextBlock)
        {
            if (!configured || des1 == null || des2 == null || des3 == null) throw new InvalidOperationException("Round keys not configured.");
            if (plaintextBlock == null) throw new ArgumentNullException(nameof(plaintextBlock));
            if (plaintextBlock.Length != BlockSizeBytes) throw new ArgumentException($"Plaintext block must be {BlockSizeBytes} bytes.");

            var t1 = des1.EncryptWithConfiguredKeys(plaintextBlock);
            var t2 = des2.DecryptWithConfiguredKeys(t1);
            var t3 = des3.EncryptWithConfiguredKeys(t2);
            return t3;
        }

        public byte[] DecryptWithConfiguredKeys(byte[] ciphertextBlock)
        {
            if (!configured || des1 == null || des2 == null || des3 == null) throw new InvalidOperationException("Round keys not configured.");
            if (ciphertextBlock == null) throw new ArgumentNullException(nameof(ciphertextBlock));
            if (ciphertextBlock.Length != BlockSizeBytes) throw new ArgumentException($"Ciphertext block must be {BlockSizeBytes} bytes.");

            var t1 = des3.DecryptWithConfiguredKeys(ciphertextBlock);
            var t2 = des2.EncryptWithConfiguredKeys(t1);
            var t3 = des1.DecryptWithConfiguredKeys(t2);
            return t3;
        }

        private void DisposeInternal()
        {
            try { des1?.Dispose(); } catch { }
            try { des2?.Dispose(); } catch { }
            try { des3?.Dispose(); } catch { }
            des1 = des2 = des3 = null;
            configured = false;
            twoKey = false;
        }

        public void Dispose()
        {
            DisposeInternal();
            GC.SuppressFinalize(this);
        }
    }
}