using System.Collections.Generic;

namespace Crypto.Interfaces
{
    /// <summary>
    /// Интерфейс генерации раундовых ключей
    /// </summary>
    public interface IKeySchedule
    {
        IReadOnlyList<byte[]> GenerateRoundKeys(byte[] masterKey);
    }
}