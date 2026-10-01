using System.Linq;
using Kerberos.NET.Crypto;

namespace Obol.Protocol;

/// <summary>The values of a principal that can change, replaced as a whole so readers see a consistent set.</summary>
internal sealed class PrincipalState
{
    public PrincipalState(KerberosKey[] keys, int kvno, ObolPrincipalFlag flags, string[] aliases)
    {
        Keys = keys;
        Kvno = kvno;
        Flags = flags;
        Aliases = aliases;
    }

    /// <summary>The long-term keys in order of preference, the first is used to encrypt tickets.</summary>
    public KerberosKey[] Keys { get; }

    public int Kvno { get; }

    public ObolPrincipalFlag Flags { get; }

    /// <summary>The other names the principal can be found by.</summary>
    public string[] Aliases { get; }

    /// <summary>The encryption types of the keys in order of preference.</summary>
    public ObolEncryptionType[] EncryptionTypes => [.. Keys.Select(k => (ObolEncryptionType)k.EncryptionType)];

    public KerberosKey? GetKey(EncryptionType etype) => Keys.FirstOrDefault(k => k.EncryptionType == etype);
}
