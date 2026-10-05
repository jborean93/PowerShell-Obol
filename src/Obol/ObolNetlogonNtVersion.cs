using System;

namespace Obol;

/// <summary>
/// The <c>NETLOGON_NT_VERSION</c> flags of the <c>NtVer</c> value of an LDAP ping, which select the form of the
/// reply, MS-ADTS 6.3.1.1.
/// </summary>
[Flags]
public enum ObolNetlogonNtVersion : uint
{
    /// <summary>No flags.</summary>
    None = 0,

    /// <summary>A NETLOGON_SAM_LOGON_RESPONSE_NT40 reply (<c>NETLOGON_NT_VERSION_1</c>).</summary>
    V1 = 0x00000001,

    /// <summary>A NETLOGON_SAM_LOGON_RESPONSE reply (<c>NETLOGON_NT_VERSION_5</c>).</summary>
    V5 = 0x00000002,

    /// <summary>A NETLOGON_SAM_LOGON_RESPONSE_EX reply (<c>NETLOGON_NT_VERSION_5EX</c>).</summary>
    V5Ex = 0x00000004,

    /// <summary>The reply includes the DC address (<c>NETLOGON_NT_VERSION_5EX_WITH_IP</c>).</summary>
    V5ExWithIp = 0x00000008,

    /// <summary>The reply includes the next closest site (<c>NETLOGON_NT_VERSION_WITH_CLOSEST_SITE</c>).</summary>
    WithClosestSite = 0x00000010,

    /// <summary>The DC must not emulate an NT 4.0 DC (<c>NETLOGON_NT_VERSION_AVOID_NT4EMUL</c>).</summary>
    AvoidNt4Emulation = 0x01000000,

    /// <summary>The ping is from a PDC (<c>NETLOGON_NT_VERSION_PDC</c>).</summary>
    Pdc = 0x10000000,

    /// <summary>Not used (<c>NETLOGON_NT_VERSION_IP</c>).</summary>
    Ip = 0x20000000,

    /// <summary>The ping is from the local machine (<c>NETLOGON_NT_VERSION_LOCAL</c>).</summary>
    Local = 0x40000000,

    /// <summary>The ping is from a global catalog (<c>NETLOGON_NT_VERSION_GC</c>).</summary>
    Gc = 0x80000000,
}
