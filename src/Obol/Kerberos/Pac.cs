namespace Obol.Kerberos;

/// <summary>
/// A privilege attribute certificate, MS-PAC, the authorization data Windows puts in a ticket with the user's SIDs
/// and groups. The buffers are the raw PACTYPE entries, the typed properties the decoded ones Obol understands.
/// </summary>
public sealed class Pac
{
    internal Pac() { }

    /// <summary>The PACTYPE version, always 0.</summary>
    public int Version { get; internal init; }

    /// <summary>Every buffer of the PAC with its raw bytes, including the signatures.</summary>
    public PacBuffer[] Buffer { get; internal init; } = [];

    /// <summary>The KERB_VALIDATION_INFO buffer, null if there is none or it could not be decoded.</summary>
    public PacLogonInfo? LogonInfo { get; internal init; }

    /// <summary>The PAC_CLIENT_INFO buffer, null if there is none or it could not be decoded.</summary>
    public PacClientInfo? ClientInfo { get; internal init; }

    /// <summary>The UPN_DNS_INFO buffer, null if there is none or it could not be decoded.</summary>
    public PacUpnDnsInfo? UpnDnsInfo { get; internal init; }

    public override string ToString() => LogonInfo is null
        ? $"PAC with {Buffer.Length} buffers"
        : $"PAC for {LogonInfo.DomainName}\\{LogonInfo.UserName}, {Buffer.Length} buffers";
}
