namespace Crypto.Interfaces
{
    /// <summary>
    /// Интерфейс симметричного шифра
    /// </summary>
    public interface ISymmetricCipher
    {
        byte[] Encrypt(byte[] plaintextBlock, byte[] key);
        byte[] Decrypt(byte[] ciphertextBlock, byte[] key);

        // методы с предварительно настроенными ключами
        void ConfigureRoundKeys(byte[] key); // предварительная генерация раундовых ключей
        byte[] EncryptWithConfiguredKeys(byte[] plaintextBlock);
        byte[] DecryptWithConfiguredKeys(byte[] ciphertextBlock);
    }
}