using Crypto.Interfaces;
using System;
using System.Collections.Generic;

namespace Crypto.DES
{
    public class DESCipher : ISymmetricCipher, IDisposable
    {
        private IReadOnlyList<byte[]>? roundKeys;
        private readonly DESKeySchedule ks = new DESKeySchedule();
        private readonly DESAlgorithm alg = new DESAlgorithm();
        private bool disposed = false;

        public int BlockSizeBytes => 8; // размер блока в байтах

        public void ConfigureRoundKeys(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != 8) throw new ArgumentException("DES key must be 8 bytes");
            roundKeys = ks.GenerateRoundKeys(key);
        }

        public byte[] Encrypt(byte[] plaintextBlock, byte[] key)
        {
            if (plaintextBlock == null) throw new ArgumentNullException(nameof(plaintextBlock));
            if (key == null) throw new ArgumentNullException(nameof(key));
            var rks = ks.GenerateRoundKeys(key);
            return alg.EncryptBlock(plaintextBlock, rks);
        }

        public byte[] Decrypt(byte[] ciphertextBlock, byte[] key)
        {
            if (ciphertextBlock == null) throw new ArgumentNullException(nameof(ciphertextBlock));
            if (key == null) throw new ArgumentNullException(nameof(key));
            var rks = ks.GenerateRoundKeys(key);
            return alg.DecryptBlock(ciphertextBlock, rks);
        }

        /// <summary>
        /// Метод шифрования с предварительно сконфигурированными ключами
        /// </summary>
        /// <param name="plaintextBlock">блок открытого текста</param>
        /// <returns></returns>
        public byte[] EncryptWithConfiguredKeys(byte[] plaintextBlock)
        {
            if (roundKeys == null) throw new InvalidOperationException("Round keys not configured.");
            return alg.EncryptBlock(plaintextBlock, roundKeys);
        }

        public byte[] DecryptWithConfiguredKeys(byte[] ciphertextBlock)
        {
            if (roundKeys == null) throw new InvalidOperationException("Round keys not configured.");
            return alg.DecryptBlock(ciphertextBlock, roundKeys);
        }

        public void Dispose()
        {
            if (disposed) return;
            if (roundKeys != null)
            {
                try
                {
                    foreach (var rk in roundKeys)
                    {
                        if (rk != null)
                        {
                            for (int i = 0; i < rk.Length; i++) 
                                rk[i] = 0;
                        }
                    }
                }
                catch { }
                roundKeys = null;
            }

            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}