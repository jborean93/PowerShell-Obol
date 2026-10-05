using System.Linq;
using Kerberos.NET.Crypto;
using Obol.Kerberos;
using EncryptionType = Obol.Kerberos.EncryptionType;

namespace Obol.Protocol;

/// <summary>The values of a principal that can change, replaced as a whole so readers see a consistent set.</summary>
internal sealed class PrincipalState
{
    public PrincipalState(KerberosKey[] keys, int kvno, PacUserAccountControl flags, string[] aliases)
    {
        Keys = keys;
        Kvno = kvno;
        Flags = flags;
        Aliases = aliases;
    }

    /// <summary>The long-term keys in order of preference, the first is used to encrypt tickets.</summary>
    public KerberosKey[] Keys { get; }

    public int Kvno { get; }

    public PacUserAccountControl Flags { get; }

    /// <summary>The other names the principal can be found by.</summary>
    public string[] Aliases { get; }

    /// <summary>The encryption types of the keys in order of preference.</summary>
    public EncryptionType[] EncryptionTypes => [.. Keys.Select(k => k.EncryptionType.ToObol())];

    public KerberosKey? GetKey(EncryptionType etype)
        => Keys.FirstOrDefault(k => k.EncryptionType.ToObol() == etype);
}
