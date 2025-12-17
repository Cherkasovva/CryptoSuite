namespace Crypto.Interfaces
{
    /// <summary>
    /// Интерфейс раунд-Шифрование
    /// </summary>
    public interface IRoundFunction
    {
        byte[] Transform(byte[] inputBlock, byte[] roundKey);
    }
}