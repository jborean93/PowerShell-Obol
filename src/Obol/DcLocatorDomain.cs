using System;
using System.Collections.Generic;
using System.Net;

namespace Obol;

/// <summary>A realm the DC locator stub answers DNS queries and LDAP pings for.</summary>
/// <param name="DnsName">The realm as a DNS domain name, in lowercase.</param>
/// <param name="NetbiosName">The NetBIOS domain name returned in the LDAP ping, the first label in uppercase.</param>
/// <param name="DomainGuid">The domain GUID returned in the LDAP ping.</param>
/// <param name="Kdcs">
/// The host name and address of each KDC, the host names are under <paramref name="DnsName"/>.
/// </param>
internal sealed record DcLocatorDomain(
    string DnsName,
    string NetbiosName,
    Guid DomainGuid,
    IReadOnlyList<(string HostName, IPAddress Address)> Kdcs)
{
    /// <summary>The longest NetBIOS name.</summary>
    private const int MaxNetbiosLength = 15;

    /// <summary>Builds the domain for a realm, each KDC is named kdc1, kdc2, ... under the realm.</summary>
    /// <param name="realm">The realm, a DNS name.</param>
    /// <param name="addresses">The address of each KDC for the realm.</param>
    public static DcLocatorDomain Create(string realm, IReadOnlyList<IPAddress> addresses)
    {
        string dnsName = realm.ToLowerInvariant();
        string netbios = dnsName.Split('.')[0].ToUpperInvariant();
        if (netbios.Length > MaxNetbiosLength)
        {
            netbios = netbios[..MaxNetbiosLength];
        }

        List<(string, IPAddress)> kdcs = [];
        for (int i = 0; i < addresses.Count; i++)
        {
            kdcs.Add(($"kdc{i + 1}.{dnsName}", addresses[i]));
        }
        return new(dnsName, netbios, Guid.NewGuid(), kdcs);
    }
}
