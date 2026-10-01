using System;
using System.Buffers.Binary;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;

namespace Obol.Protocol;

/// <summary>A principal found for a request, with its state at the time of the request.</summary>
internal sealed class KdcPrincipal
{
    private const SidAttributes GroupAttributes = SidAttributes.SE_GROUP_MANDATORY
        | SidAttributes.SE_GROUP_ENABLED_BY_DEFAULT
        | SidAttributes.SE_GROUP_ENABLED;

    // The PAC UserAccountControl uses the MS-SAMR 2.2.1.12 USER_* codes, not the LDAP ADS_UF_* values of the
    // Kerberos.NET enum.
    private const uint UserNormalAccount = 0x00000010;
    private const uint UserTrustedForDelegation = 0x00002000;
    private const uint UserNotDelegated = 0x00004000;
    private const uint UserDontRequirePreauth = 0x00010000;

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

    // The MS-KILE 2.2.7 bit flags of the encryption types the store can create keys for. The Kerberos.NET
    // SupportedEncryptionTypes enum gives the SHA-2 types the wrong values (0x20 is AES256-CTS-HMAC-SHA1-96-SK).
    private const uint SupportedAes128Sha1 = 0x00000008;
    private const uint SupportedAes256Sha1 = 0x00000010;
    private const uint SupportedAes128Sha256 = 0x00000040;
    private const uint SupportedAes256Sha384 = 0x00000080;

    /// <summary>
    /// The encryption types of the principal's keys as the 32-bit little endian PA-SUPPORTED-ENCTYPES value.
    /// </summary>
    public ReadOnlyMemory<byte> EncodeSupportedEncryptionTypes()
    {
        uint types = 0;
        foreach (KerberosKey key in State.Keys)
        {
            types |= key.EncryptionType switch
            {
                EncryptionType.AES128_CTS_HMAC_SHA1_96 => SupportedAes128Sha1,
                EncryptionType.AES256_CTS_HMAC_SHA1_96 => SupportedAes256Sha1,
                EncryptionType.AES128_CTS_HMAC_SHA256_128 => SupportedAes128Sha256,
                EncryptionType.AES256_CTS_HMAC_SHA384_192 => SupportedAes256Sha384,
                // The store only creates the supported types, a new one must be mapped here.
                _ => throw new ArgumentOutOfRangeException(nameof(key.EncryptionType), key.EncryptionType,
                    "The encryption type has no PA-SUPPORTED-ENCTYPES value"),
            };
        }

        byte[] value = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(value, types);
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
        uint uac = UserNormalAccount;
        if (State.Flags.HasFlag(ObolPrincipalFlag.DoesNotRequirePreAuth))
        {
            uac |= UserDontRequirePreauth;
        }
        if (State.Flags.HasFlag(ObolPrincipalFlag.NotDelegated))
        {
            uac |= UserNotDelegated;
        }
        if (State.Flags.HasFlag(ObolPrincipalFlag.TrustedForDelegation))
        {
            uac |= UserTrustedForDelegation;
        }

        return new PrivilegedAttributeCertificate
        {
            LogonInfo = new PacLogonInfo
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
                        Attributes = GroupAttributes,
                    },
                ],
                LogonTime = authTime,
                UserAccountControl = (UserAccountControlFlags)uac,
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
