using System;
using Obol.Kerberos;
using PrincipalName = Obol.Protocol.PrincipalName;

namespace Obol;

/// <summary>A key of a principal in a keytab.</summary>
public sealed class ObolKeytabEntry
{
    internal ObolKeytabEntry(
        string realm,
        string[] components,
        PrincipalNameType nameType,
        DateTime timestamp,
        int kvno,
        EncryptionType encryptionType,
        byte[] key)
    {
        Realm = realm;
        Components = components;
        Name = PrincipalName.Unparse(components);
        NameType = nameType;

        // Keytabs hold UTC seconds, shown in local time like ObolKdc.StartTime and file times.
        Timestamp = timestamp.ToLocalTime();
        Kvno = kvno;
        EncryptionType = encryptionType;
        Key = key;
    }

    /// <summary>
    /// The principal name without the realm, such as <c>HTTP/web.example.test</c>, with '/', '@' and '\' in a
    /// component escaped with '\'.
    /// </summary>
    public string Name { get; }

    /// <summary>The realm of the principal.</summary>
    public string Realm { get; }

    /// <summary>The principal name with the realm, such as <c>HTTP/web.example.test@EXAMPLE.TEST</c>.</summary>
    public string FullName => $"{Name}@{Realm}";

    /// <summary>
    /// The name type of the principal, usually <see cref="PrincipalNameType.Principal"/>. A type without a name
    /// is shown as its number.
    /// </summary>
    public PrincipalNameType NameType { get; }

    /// <summary>The local time the entry was written, the keytab stores it in UTC.</summary>
    public DateTime Timestamp { get; }

    /// <summary>The version number of the key.</summary>
    public int Kvno { get; }

    /// <summary>
    /// The encryption type of the key. A keytab can hold types a principal cannot have keys for, such as
    /// <see cref="EncryptionType.Rc4Hmac"/>, those entries are read and written but not used for keys.
    /// </summary>
    public EncryptionType EncryptionType { get; }

    /// <summary>The key value.</summary>
    public byte[] Key { get; }

    /// <summary>The name components, such as <c>HTTP</c> and <c>web.example.test</c>.</summary>
    internal string[] Components { get; }

    public override string ToString() => $"{FullName} {EncryptionType} kvno {Kvno}";
}
