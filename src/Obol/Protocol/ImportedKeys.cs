namespace Obol.Protocol;

/// <summary>Existing long-term keys to give a principal, such as keys read from a keytab.</summary>
/// <param name="Kvno">The key version number the keys have.</param>
/// <param name="Keys">The encryption types and key values in order of preference.</param>
internal sealed record ImportedKeys(int Kvno, (ObolEncryptionType Type, byte[] Value)[] Keys);
