namespace Obol.Kerberos;

/// <summary>The UPN_DNS_INFO buffer of a PAC, MS-PAC 2.10, the user principal name and DNS domain of the client.
/// </summary>
public sealed class PacUpnDnsInfo
{
    internal PacUpnDnsInfo(string upn, string dnsDomainName, PacUpnDnsFlag flag)
    {
        Upn = upn;
        DnsDomainName = dnsDomainName;
        Flag = flag;
    }

    /// <summary>The user principal name, such as <c>user@example.test</c>.</summary>
    public string Upn { get; }

    /// <summary>The DNS name of the domain.</summary>
    public string DnsDomainName { get; }

    /// <summary>The flags.</summary>
    public PacUpnDnsFlag Flag { get; }

    public override string ToString() => Upn;
}
