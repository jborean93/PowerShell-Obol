using System;

namespace Obol.Kerberos;

/// <summary>The UserFlags of the PAC logon information, MS-PAC 2.5.</summary>
[Flags]
public enum PacUserFlag : uint
{
    None = 0,

    /// <summary>The user logged on as a guest.</summary>
    Guest = 0x00000001,

    /// <summary>No encryption is available.</summary>
    NoEncryption = 0x00000002,

    /// <summary>The LAN Manager key was used.</summary>
    LanManKey = 0x00000008,

    /// <summary>The ExtraSids field is used.</summary>
    ExtraSids = 0x00000020,

    /// <summary>A sub-authentication package was used.</summary>
    SubAuthentication = 0x00000040,

    /// <summary>The account is a machine account.</summary>
    MachineAccount = 0x00000080,

    /// <summary>NTLMv2 was used.</summary>
    NtlmV2 = 0x00000100,

    /// <summary>The ResourceGroupIds field is used.</summary>
    ResourceGroups = 0x00000200,

    /// <summary>The ProfilePath field is used.</summary>
    ProfilePath = 0x00000400,

    /// <summary>The account logged on with a smart card or certificate.</summary>
    Pkinit = 0x00010000,

    /// <summary>The logon was a grace logon.</summary>
    GraceLogon = 0x01000000,
}
