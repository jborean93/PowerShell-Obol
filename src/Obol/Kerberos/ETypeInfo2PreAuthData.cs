using System.Linq;

namespace Obol.Kerberos;

/// <summary>
/// PA-ETYPE-INFO2, the encryption types and salts the KDC accepts, sent with PreAuthRequired and in an AS-REP.
/// </summary>
public sealed class ETypeInfo2PreAuthData : PreAuthData
{
    internal ETypeInfo2PreAuthData(byte[] value, ETypeInfo2Entry[] entries)
        : base(PreAuthDataType.ETypeInfo2, value)
    {
        Entry = entries;
    }

    /// <summary>The entries, one per encryption type.</summary>
    public ETypeInfo2Entry[] Entry { get; }

    public override string ToString() => $"{Type} {string.Join(", ", Entry.Select(e => e.ToString()))}";
}
