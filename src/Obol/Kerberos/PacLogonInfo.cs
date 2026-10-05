using System;

namespace Obol.Kerberos;

/// <summary>The KERB_VALIDATION_INFO buffer of a PAC, MS-PAC 2.5, the logon information with the user's SIDs and
/// groups.</summary>
public sealed class PacLogonInfo
{
    internal PacLogonInfo() { }

    /// <summary>The local time the user logged on, the AuthTime of the ticket.</summary>
    public DateTime? LogonTime { get; internal init; }

    /// <summary>The local time the user must log off, null for never.</summary>
    public DateTime? LogoffTime { get; internal init; }

    /// <summary>The local time the user is kicked off, null for never.</summary>
    public DateTime? KickOffTime { get; internal init; }

    /// <summary>The local time the password was last set, null if not set.</summary>
    public DateTime? PasswordLastSet { get; internal init; }

    /// <summary>The local time the password can be changed from, null if not set.</summary>
    public DateTime? PasswordCanChange { get; internal init; }

    /// <summary>The local time the password must be changed by, null for never.</summary>
    public DateTime? PasswordMustChange { get; internal init; }

    /// <summary>The SAM account name of the user.</summary>
    public string UserName { get; internal init; } = "";

    /// <summary>The display name of the user.</summary>
    public string UserDisplayName { get; internal init; } = "";

    /// <summary>The logon script path.</summary>
    public string LogonScript { get; internal init; } = "";

    /// <summary>The profile path.</summary>
    public string ProfilePath { get; internal init; } = "";

    /// <summary>The home directory.</summary>
    public string HomeDirectory { get; internal init; } = "";

    /// <summary>The drive letter the home directory is mapped to.</summary>
    public string HomeDrive { get; internal init; } = "";

    /// <summary>How many times the user has logged on.</summary>
    public short LogonCount { get; internal init; }

    /// <summary>How many bad passwords were tried since the last logon.</summary>
    public short BadPasswordCount { get; internal init; }

    /// <summary>The RID of the user.</summary>
    public uint UserId { get; internal init; }

    /// <summary>The RID of the user's primary group.</summary>
    public uint PrimaryGroupId { get; internal init; }

    /// <summary>The groups of the user in its domain.</summary>
    public PacGroupMembership[] GroupId { get; internal init; } = [];

    /// <summary>The user flags.</summary>
    public PacUserFlag UserFlag { get; internal init; }

    /// <summary>The user session key, zeros for Kerberos.</summary>
    public byte[] UserSessionKey { get; internal init; } = [];

    /// <summary>The NetBIOS name of the server that issued the PAC.</summary>
    public string ServerName { get; internal init; } = "";

    /// <summary>The NetBIOS name of the user's domain.</summary>
    public string DomainName { get; internal init; } = "";

    /// <summary>The SID of the user's domain.</summary>
    public string DomainSid { get; internal init; } = "";

    /// <summary>The account control values of the user.</summary>
    public PacUserAccountControl UserAccountControl { get; internal init; }

    /// <summary>SIDs of the user outside its domain, set when <see cref="UserFlag"/> has <c>ExtraSids</c>.</summary>
    public PacSidAttributes[] ExtraSid { get; internal init; } = [];

    /// <summary>The SID of the resource domain, set when <see cref="UserFlag"/> has <c>ResourceGroups</c>.</summary>
    public string? ResourceDomainSid { get; internal init; }

    /// <summary>The groups in the resource domain.</summary>
    public PacGroupMembership[] ResourceGroupId { get; internal init; } = [];

    /// <summary>The SID of the user, the domain SID with <see cref="UserId"/>.</summary>
    public string UserSid => $"{DomainSid}-{UserId}";

    /// <summary>The SID of the user's primary group, the domain SID with <see cref="PrimaryGroupId"/>.</summary>
    public string PrimaryGroupSid => $"{DomainSid}-{PrimaryGroupId}";

    public override string ToString() => $"{DomainName}\\{UserName} ({UserSid})";
}
