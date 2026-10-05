using System;
using System.Buffers.Binary;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Obol.Kerberos;
using EncryptionType = Obol.Kerberos.EncryptionType;
using KrbPacLogonInfo = Kerberos.NET.Entities.Pac.PacLogonInfo;

namespace Obol.Protocol;

/// <summary>A principal found for a request, with its state at the time of the request.</summary>
internal sealed class KdcPrincipal
{
    private const PacGroupAttribute GroupAttributes = PacGroupAttribute.Mandatory
        | PacGroupAttribute.EnabledByDefault
        | PacGroupAttribute.Enabled;

    public KdcPrincipal(ObolPrincipal principal)
    {
        Principal = principal;

        // The values used for the whole request, a change made during the request applies to the next one.
        State = principal.State;
    }

    public ObolPrincipal Principal { get; }

    public PrincipalState State { get; }

    /// <summary>The preferred key, used to encrypt tickets for the principal.</summary>
    public KerberosKey PreferredKey => State.Keys[0];

    public KerberosKey? GetKey(EncryptionType etype) => State.GetKey(etype);

    /// <summary>
    /// The encryption types of the principal's keys as the 32-bit little endian PA-SUPPORTED-ENCTYPES value.
    /// </summary>
    public ReadOnlyMemory<byte> EncodeSupportedEncryptionTypes()
    {
        SupportedEncryptionType types = SupportedEncryptionType.None;
        foreach (KerberosKey key in State.Keys)
        {
            EncryptionType etype = key.EncryptionType.ToObol();
            types |= etype switch
            {
                EncryptionType.Aes128Sha1 => SupportedEncryptionType.Aes128Sha1,
                EncryptionType.Aes256Sha1 => SupportedEncryptionType.Aes256Sha1,
                EncryptionType.Aes128Sha256 => SupportedEncryptionType.Aes128Sha256,
                EncryptionType.Aes256Sha384 => SupportedEncryptionType.Aes256Sha384,
                // The store only creates the supported types, a new one must be mapped here.
                _ => throw new ArgumentOutOfRangeException(nameof(key.EncryptionType), etype,
                    "The encryption type has no PA-SUPPORTED-ENCTYPES value"),
            };
        }

        byte[] value = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(value, (uint)types);
        return value;
    }

    /// <summary>
    /// Creates a minimal PAC with the user and its primary group, enough for Windows to accept the ticket.
    /// </summary>
    /// <param name="authTime">The time the client authenticated, used as the logon time.</param>
    public PrivilegedAttributeCertificate GeneratePac(DateTimeOffset authTime)
    {
        PrincipalStore store = Principal.Store;
        SecurityIdentifier domainSid = store.DomainSid;
        // The flags of a principal are the PAC values, only the supported bits are set on a principal.
        PacUserAccountControl uac = PacUserAccountControl.NormalAccount
            | (State.Flags & PrincipalStore.SupportedAccountControl);

        return new PrivilegedAttributeCertificate
        {
            LogonInfo = new KrbPacLogonInfo
            {
                DomainName = GetNetBiosName(store.Realm),
                UserName = Principal.Name,
                UserDisplayName = Principal.Name,
                DomainSid = domainSid,
                UserSid = new SecurityIdentifier(domainSid, Principal.Rid),
                GroupSid = new SecurityIdentifier(domainSid, PrincipalStore.DomainUsersRid),
                GroupIds =
                [
                    new GroupMembership
                    {
                        RelativeId = PrincipalStore.DomainUsersRid,
                        Attributes = GroupAttributes.ToKerberosNet(),
                    },
                ],
                LogonTime = authTime,
                UserAccountControl = uac.ToKerberosNet(),
            },
        };
    }

    /// <summary>
    /// The NetBIOS domain name used in the PAC, the first label of the realm limited to 15 characters.
    /// </summary>
    private static string GetNetBiosName(string realm)
    {
        string label = realm.Split('.')[0].ToUpperInvariant();
        return label.Length > 15 ? label[..15] : label;
    }
}
