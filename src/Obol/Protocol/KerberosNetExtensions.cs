using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Obol.Kerberos;
using AddressType = Obol.Kerberos.AddressType;
using AuthorizationDataType = Obol.Kerberos.AuthorizationDataType;
using ChecksumType = Obol.Kerberos.ChecksumType;
using EncryptionType = Obol.Kerberos.EncryptionType;
using KeyUsage = Obol.Kerberos.KeyUsage;
using KrbAddressType = Kerberos.NET.Entities.AddressType;
using KrbAuthorizationDataType = Kerberos.NET.Entities.AuthorizationDataType;
using KrbChecksumType = Kerberos.NET.Crypto.ChecksumType;
using KrbEncryptionType = Kerberos.NET.Crypto.EncryptionType;
using KrbKeyUsage = Kerberos.NET.Crypto.KeyUsage;
using KrbMessageType = Kerberos.NET.Entities.MessageType;
using KrbPrincipalNameType = Kerberos.NET.Entities.PrincipalNameType;
using MessageType = Obol.Kerberos.MessageType;
using PrincipalNameType = Obol.Kerberos.PrincipalNameType;

namespace Obol.Protocol;

/// <summary>
/// Converts the Obol enums, the source of truth for the Kerberos constants, to and from the Kerberos.NET enums its
/// entities use. Every crossing of that boundary goes through here so the rest of the protocol code only names Obol
/// constants. Both sides use the wire values so each conversion keeps the bits, a value Obol has no name for stays
/// as its number.
/// </summary>
internal static class KerberosNetExtensions
{
    public static KerberosErrorCode ToKerberosNet(this ErrorCode value) => (KerberosErrorCode)(int)value;

    public static ErrorCode ToObol(this KerberosErrorCode value) => (ErrorCode)(int)value;

    public static TicketFlags ToKerberosNet(this TicketFlag value) => (TicketFlags)(int)(uint)value;

    public static TicketFlag ToObol(this TicketFlags value) => (TicketFlag)(uint)(int)value;

    public static KdcOptions ToKerberosNet(this KdcOption value) => (KdcOptions)(int)(uint)value;

    public static KdcOption ToObol(this KdcOptions value) => (KdcOption)(uint)(int)value;

    public static ApOption ToObol(this ApOptions value) => (ApOption)(uint)(int)value;

    public static PaDataType ToKerberosNet(this PreAuthDataType value) => (PaDataType)(int)value;

    public static PreAuthDataType ToObol(this PaDataType value) => (PreAuthDataType)(int)value;

    public static KrbAuthorizationDataType ToKerberosNet(this AuthorizationDataType value)
        => (KrbAuthorizationDataType)(int)value;

    public static AuthorizationDataType ToObol(this KrbAuthorizationDataType value)
        => (AuthorizationDataType)(int)value;

    public static KrbChecksumType ToKerberosNet(this ChecksumType value) => (KrbChecksumType)(int)value;

    public static ChecksumType ToObol(this KrbChecksumType value) => (ChecksumType)(int)value;

    public static KrbKeyUsage ToKerberosNet(this KeyUsage value) => (KrbKeyUsage)(int)value;

    public static KrbEncryptionType ToKerberosNet(this EncryptionType value) => (KrbEncryptionType)(int)value;

    public static EncryptionType ToObol(this KrbEncryptionType value) => (EncryptionType)(int)value;

    public static KrbMessageType ToKerberosNet(this MessageType value) => (KrbMessageType)(int)value;

    public static MessageType ToObol(this KrbMessageType value) => (MessageType)(int)value;

    public static PrincipalNameType ToObol(this KrbPrincipalNameType value) => (PrincipalNameType)(int)value;

    public static AddressType ToObol(this KrbAddressType value) => (AddressType)(int)value;

    public static SidAttributes ToKerberosNet(this PacGroupAttribute value) => (SidAttributes)(uint)value;

    public static PacGroupAttribute ToObol(this SidAttributes value) => (PacGroupAttribute)(uint)value;

    /// <summary>
    /// The PAC field holds the MS-SAMR USER_* values that <see cref="PacUserAccountControl"/> names, the Kerberos.NET
    /// enum names the LDAP ADS_UF_* values so only the bits are kept.
    /// </summary>
    public static UserAccountControlFlags ToKerberosNet(this PacUserAccountControl value)
        => (UserAccountControlFlags)(int)(uint)value;

    public static PacUserAccountControl ToObol(this UserAccountControlFlags value)
        => (PacUserAccountControl)(uint)(int)value;

    public static PacUserFlag ToObol(this UserFlags value) => (PacUserFlag)(uint)(int)value;

    public static PacUpnDnsFlag ToObol(this UpnDomainFlags value) => (PacUpnDnsFlag)(int)value;
}
