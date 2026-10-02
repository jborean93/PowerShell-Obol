using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Text;

namespace Obol.Commands;

/// <summary>Creates a krb5.conf for MIT krb5 or Heimdal that points the realms of KDCs at their endpoints.</summary>
internal static class Krb5Config
{
    /// <summary>Characters that end a relation name or start a section, comment or group in a krb5.conf.</summary>
    private static readonly char[] s_invalidRealmChars = ['=', '[', ']', '{', '}', '#', ';', '"'];

    /// <summary>Checks the KDC is running and its realm can be written in a krb5.conf.</summary>
    /// <returns>The error to write, or null if the KDC can be used.</returns>
    public static ErrorRecord? CheckKdc(ObolKdc kdc)
    {
        if (kdc.State != ObolKdcState.Running)
        {
            return new ErrorRecord(
                new InvalidOperationException($"The KDC for '{kdc.Realm}' is {kdc.State}"),
                "KdcNotRunning",
                ErrorCategory.InvalidOperation,
                kdc);
        }

        // A relation name ends at whitespace or '=', the other characters would be read as part of the syntax.
        if (kdc.Realm.Any(char.IsWhiteSpace) || kdc.Realm.IndexOfAny(s_invalidRealmChars) != -1)
        {
            return new ErrorRecord(
                new ArgumentException(
                    $"The realm '{kdc.Realm}' cannot be written in a krb5.conf, it must not contain whitespace or " +
                    string.Join(" ", s_invalidRealmChars)),
                "InvalidKrb5ConfigRealm",
                ErrorCategory.InvalidArgument,
                kdc);
        }

        return null;
    }

    /// <summary>The provider Default stands for on the current platform, Heimdal on macOS and MIT elsewhere.</summary>
    public static ObolKrb5Provider GetPlatformProvider()
        => OperatingSystem.IsMacOS() ? ObolKrb5Provider.Heimdal : ObolKrb5Provider.Mit;

    /// <summary>Checks the provider is a defined value.</summary>
    /// <returns>The error to write, or null if the provider is valid.</returns>
    public static ErrorRecord? CheckProvider(ObolKrb5Provider provider)
    {
        // PowerShell binding rejects undefined values but [Enum]::ToObject can still create one.
        if (Enum.IsDefined(provider))
        {
            return null;
        }

        return new ErrorRecord(
            new ArgumentException(
                $"Provider '{provider}' is not supported, valid values are " +
                string.Join(", ", Enum.GetNames<ObolKrb5Provider>())),
            "InvalidProvider",
            ErrorCategory.InvalidArgument,
            provider);
    }

    /// <summary>Creates the krb5.conf content, the first KDC's realm is the default realm.</summary>
    /// <param name="kdcs">The KDCs to add, each checked with <see cref="CheckKdc"/>.</param>
    /// <param name="provider">The Kerberos implementation the content is for, Default picks the platform's.</param>
    public static string Create(IReadOnlyList<ObolKdc> kdcs, ObolKrb5Provider provider)
    {
        if (provider == ObolKrb5Provider.Default)
        {
            provider = GetPlatformProvider();
        }

        StringBuilder sb = new();
        sb.Append("[libdefaults]\n");
        sb.Append($"    default_realm = {kdcs[0].Realm}\n");

        // Only use the KDCs listed below and the host names as given, test host names are rarely in DNS.
        sb.Append("    dns_lookup_kdc = false\n");
        sb.Append("    dns_lookup_realm = false\n");
        sb.Append("    dns_canonicalize_hostname = false\n");
        if (provider == ObolKrb5Provider.Mit)
        {
            sb.Append("    rdns = false\n");

            // MIT has no per KDC transport, a message over this size is sent over TCP first and then over UDP if TCP
            // fails. A limit of 1 sends everything over TCP first so a KDC without UDP is reached straight away.
            if (kdcs.Any(k => !k.Transport.HasFlag(ObolKdcTransport.Udp)))
            {
                sb.Append("    udp_preference_limit = 1\n");
            }
        }

        // KDCs for the same realm are listed together so a client can use any of them.
        sb.Append("\n[realms]\n");
        foreach (IGrouping<string, ObolKdc> realm in kdcs.GroupBy(k => k.Realm, StringComparer.Ordinal))
        {
            sb.Append($"    {realm.Key} = {{\n");
            foreach (ObolKdc kdc in realm)
            {
                sb.Append($"        kdc = {GetTransportPrefix(kdc, provider)}{GetKdcAddress(kdc.Endpoint)}\n");
            }
            sb.Append("    }\n");
        }

        // Map hosts under the realm name in lowercase to the realm, such as web.example.test to EXAMPLE.TEST.
        sb.Append("\n[domain_realm]\n");
        HashSet<string> domains = new(StringComparer.OrdinalIgnoreCase);
        foreach (ObolKdc kdc in kdcs)
        {
            string domain = kdc.Realm.ToLowerInvariant();
            if (domains.Add(domain))
            {
                sb.Append($"    .{domain} = {kdc.Realm}\n");
                sb.Append($"    {domain} = {kdc.Realm}\n");
            }
        }

        return sb.ToString();
    }

    /// <summary>The transport prefix of a kdc entry, Heimdal only.</summary>
    /// <remarks>
    /// Heimdal picks the transport of an entry without a prefix by the message size (large_message_size) and does
    /// not try the other one if it fails, so a KDC with one transport is given that prefix. MIT reads the prefix as
    /// part of the host name.
    /// </remarks>
    private static string GetTransportPrefix(ObolKdc kdc, ObolKrb5Provider provider)
    {
        if (provider != ObolKrb5Provider.Heimdal)
        {
            return "";
        }

        return kdc.Transport switch
        {
            ObolKdcTransport.Tcp => "tcp/",
            ObolKdcTransport.Udp => "udp/",
            _ => "",
        };
    }

    /// <summary>The address clients use to reach the KDC, a loopback address if it listens on all addresses.</summary>
    private static string GetKdcAddress(IPEndPoint endpoint)
    {
        IPAddress address = endpoint.Address;
        if (address.Equals(IPAddress.Any))
        {
            address = IPAddress.Loopback;
        }
        else if (address.Equals(IPAddress.IPv6Any))
        {
            address = IPAddress.IPv6Loopback;
        }

        return new IPEndPoint(address, endpoint.Port).ToString();
    }
}
