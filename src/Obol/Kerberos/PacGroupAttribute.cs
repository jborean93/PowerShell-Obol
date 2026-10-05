using System;

namespace Obol.Kerberos;

/// <summary>The attributes of a group SID in the PAC logon information, the SE_GROUP_* values of MS-PAC 2.2.1.
/// </summary>
[Flags]
public enum PacGroupAttribute : uint
{
    None = 0,

    /// <summary>SE_GROUP_MANDATORY.</summary>
    Mandatory = 0x00000001,

    /// <summary>SE_GROUP_ENABLED_BY_DEFAULT.</summary>
    EnabledByDefault = 0x00000002,

    /// <summary>SE_GROUP_ENABLED.</summary>
    Enabled = 0x00000004,

    /// <summary>SE_GROUP_OWNER.</summary>
    Owner = 0x00000008,

    /// <summary>SE_GROUP_USE_FOR_DENY_ONLY.</summary>
    UseForDenyOnly = 0x00000010,

    /// <summary>SE_GROUP_INTEGRITY.</summary>
    Integrity = 0x00000020,

    /// <summary>SE_GROUP_INTEGRITY_ENABLED.</summary>
    IntegrityEnabled = 0x00000040,

    /// <summary>SE_GROUP_RESOURCE.</summary>
    Resource = 0x20000000,
}
