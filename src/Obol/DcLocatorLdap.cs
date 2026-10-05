using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Obol;

/// <summary>Answers the CLDAP "LDAP ping" the Windows DC locator sends to check a DC found through DNS.</summary>
/// <remarks>
/// The ping is an LDAP search over UDP with a filter such as <c>(&amp;(DnsDomain=x)(NtVer=...))</c> for the
/// <c>Netlogon</c> attribute, see MS-ADTS 6.3.3. The reply is a search result entry with a
/// NETLOGON_SAM_LOGON_RESPONSE_EX for the realm and a search result done, both in one datagram.
/// </remarks>
internal sealed class DcLocatorLdap
{
    /// <summary>NETLOGON_NT_VERSION_5EX_WITH_IP, the reply includes the DC address.</summary>
    private const uint NtVersion5ExWithIp = 0x8;

    /// <summary>NETLOGON_NT_VERSION_WITH_CLOSEST_SITE, the reply includes the next closest site.</summary>
    private const uint NtVersionWithClosestSite = 0x10;

    /// <summary>LOGON_SAM_LOGON_RESPONSE_EX.</summary>
    private const ushort OpcodeSamLogonResponseEx = 23;

    /// <summary>The NtVersion of the reply, NETLOGON_NT_VERSION_1 | NETLOGON_NT_VERSION_5EX.</summary>
    private const uint ReplyNtVersion = 0x5;

    /// <summary>
    /// The DS_FLAG values of a writable DC that is a KDC, LDAP server, GC and time server for the realm, the flags a
    /// Windows Server 2016 or later DC returns.
    /// </summary>
    private const uint DcFlags =
        0x00000001 | // DS_PDC_FLAG
        0x00000004 | // DS_GC_FLAG
        0x00000008 | // DS_LDAP_FLAG
        0x00000010 | // DS_DS_FLAG
        0x00000020 | // DS_KDC_FLAG
        0x00000040 | // DS_TIMESERV_FLAG
        0x00000080 | // DS_CLOSEST_FLAG
        0x00000100 | // DS_WRITABLE_FLAG
        0x00000200 | // DS_GOOD_TIMESERV_FLAG
        0x00001000 | // DS_FULL_SECRET_DOMAIN_6_FLAG
        0x00002000 | // DS_WS_FLAG
        0x00004000 | // DS_DS_8_FLAG
        0x00008000 | // DS_DS_9_FLAG
        0x00010000;  // DS_DS_10_FLAG

    /// <summary>The site the DC and every client are in.</summary>
    private const string SiteName = "Default-First-Site-Name";

    private static readonly Asn1Tag s_searchRequestTag = new(TagClass.Application, 3, isConstructed: true);
    private static readonly Asn1Tag s_searchResultEntryTag = new(TagClass.Application, 4, isConstructed: true);
    private static readonly Asn1Tag s_searchResultDoneTag = new(TagClass.Application, 5, isConstructed: true);
    private static readonly Asn1Tag s_filterAndTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag s_filterEqualityTag = new(TagClass.ContextSpecific, 3, isConstructed: true);

    private readonly IReadOnlyList<DcLocatorDomain> _domains;

    public DcLocatorLdap(IReadOnlyList<DcLocatorDomain> domains)
    {
        _domains = domains;
    }

    /// <summary>Builds the reply to an LDAP ping.</summary>
    /// <param name="request">The CLDAP request.</param>
    /// <param name="localAddress">The address the ping was received on, picks the KDC host name in the reply.</param>
    /// <returns>The reply, or null if the request is not a search request that can be answered.</returns>
    public byte[]? Process(ReadOnlyMemory<byte> request, IPAddress localAddress)
    {
        int messageId;
        Dictionary<string, byte[]> filter = new(StringComparer.OrdinalIgnoreCase);
        try
        {
            AsnReader message = new AsnReader(request, AsnEncodingRules.BER).ReadSequence();
            if (!message.TryReadInt32(out messageId))
            {
                return null;
            }
            if (message.PeekTag() != s_searchRequestTag)
            {
                return null;
            }

            AsnReader search = message.ReadSequence(s_searchRequestTag);
            search.ReadOctetString(); // baseObject
            search.ReadEncodedValue(); // scope
            search.ReadEncodedValue(); // derefAliases
            search.ReadEncodedValue(); // sizeLimit
            search.ReadEncodedValue(); // timeLimit
            search.ReadEncodedValue(); // typesOnly
            ReadFilter(search, filter);
        }
        catch (AsnContentException)
        {
            return null;
        }

        AsnWriter writer = new(AsnEncodingRules.DER);
        if (filter.TryGetValue("DnsDomain", out byte[]? dnsDomain) && FindDomain(dnsDomain) is DcLocatorDomain domain)
        {
            uint ntVersion = filter.TryGetValue("NtVer", out byte[]? ntVer) && ntVer.Length >= 4
                ? BinaryPrimitives.ReadUInt32LittleEndian(ntVer)
                : 0;
            byte[] netlogon = BuildNetlogonResponse(domain, localAddress, ntVersion);

            using (writer.PushSequence())
            {
                writer.WriteInteger(messageId);
                using (writer.PushSequence(s_searchResultEntryTag))
                {
                    writer.WriteOctetString([]);
                    using (writer.PushSequence())
                    {
                        using (writer.PushSequence())
                        {
                            writer.WriteOctetString("Netlogon"u8);
                            using (writer.PushSetOf())
                            {
                                writer.WriteOctetString(netlogon);
                            }
                        }
                    }
                }
            }
        }

        // A ping for another domain gets no entry, the locator then treats the host as not being a DC for it.
        using (writer.PushSequence())
        {
            writer.WriteInteger(messageId);
            using (writer.PushSequence(s_searchResultDoneTag))
            {
                writer.WriteEnumeratedValue(LdapResultCode.Success);
                writer.WriteOctetString([]);
                writer.WriteOctetString([]);
            }
        }
        return writer.Encode();
    }

    /// <summary>Collects the equality matches of a filter, including the ones nested in an AND.</summary>
    private static void ReadFilter(AsnReader reader, Dictionary<string, byte[]> filter)
    {
        Asn1Tag tag = reader.PeekTag();
        if (tag == s_filterAndTag)
        {
            AsnReader and = reader.ReadSetOf(s_filterAndTag);
            while (and.HasData)
            {
                ReadFilter(and, filter);
            }
        }
        else if (tag == s_filterEqualityTag)
        {
            AsnReader equality = reader.ReadSequence(s_filterEqualityTag);
            string attribute = Encoding.UTF8.GetString(equality.ReadOctetString());
            filter[attribute] = equality.ReadOctetString();
        }
        else
        {
            reader.ReadEncodedValue();
        }
    }

    private DcLocatorDomain? FindDomain(byte[] dnsDomain)
    {
        // The domain may be sent with a trailing dot.
        string name = Encoding.UTF8.GetString(dnsDomain).TrimEnd('.');
        foreach (DcLocatorDomain domain in _domains)
        {
            if (domain.DnsName.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return domain;
            }
        }
        return null;
    }

    /// <summary>Builds the NETLOGON_SAM_LOGON_RESPONSE_EX, MS-ADTS 6.3.1.9.</summary>
    internal static byte[] BuildNetlogonResponse(DcLocatorDomain domain, IPAddress localAddress, uint ntVersion)
    {
        // The KDC the ping reached, a ping to another address of the host gets the first KDC.
        (string hostName, IPAddress address) = domain.Kdcs[0];
        foreach ((string host, IPAddress kdcAddress) in domain.Kdcs)
        {
            if (kdcAddress.Equals(localAddress))
            {
                (hostName, address) = (host, kdcAddress);
                break;
            }
        }

        List<byte> buffer = new(256);
        WriteUInt16(buffer, OpcodeSamLogonResponseEx);
        WriteUInt16(buffer, 0); // Sbz
        WriteUInt32(buffer, DcFlags);
        buffer.AddRange(domain.DomainGuid.ToByteArray());
        WriteName(buffer, domain.DnsName); // DnsForestName
        WriteName(buffer, domain.DnsName); // DnsDomainName
        WriteName(buffer, hostName); // DnsHostName
        WriteLabel(buffer, domain.NetbiosName); // NetbiosDomainName
        WriteLabel(buffer, hostName.Split('.')[0].ToUpperInvariant()); // NetbiosComputerName
        WriteLabel(buffer, ""); // UserName
        WriteLabel(buffer, SiteName); // DcSiteName
        WriteLabel(buffer, SiteName); // ClientSiteName

        if ((ntVersion & NtVersion5ExWithIp) != 0)
        {
            // DcSockAddrSize and a SOCKADDR_IN, only an IPv4 address can be returned.
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                buffer.Add(16);
                buffer.Add((byte)AddressFamily.InterNetwork); // sin_family, little endian
                buffer.Add(0);
                WriteUInt16(buffer, 0); // sin_port
                buffer.AddRange(address.GetAddressBytes()); // sin_addr, network order
                buffer.AddRange(new byte[8]); // sin_zero
            }
            else
            {
                buffer.Add(0);
            }
        }
        if ((ntVersion & NtVersionWithClosestSite) != 0)
        {
            WriteLabel(buffer, ""); // NextClosestSiteName
        }

        WriteUInt32(buffer, ReplyNtVersion);
        WriteUInt16(buffer, 0xFFFF); // LmNtToken
        WriteUInt16(buffer, 0xFFFF); // Lm20Token
        return [.. buffer];
    }

    private static void WriteUInt16(List<byte> buffer, ushort value)
    {
        buffer.Add((byte)value);
        buffer.Add((byte)(value >> 8));
    }

    private static void WriteUInt32(List<byte> buffer, uint value)
    {
        WriteUInt16(buffer, (ushort)value);
        WriteUInt16(buffer, (ushort)(value >> 16));
    }

    /// <summary>Writes a dotted name as RFC 1035 labels, an empty name is just the terminator.</summary>
    private static void WriteName(List<byte> buffer, string name)
    {
        if (name.Length > 0)
        {
            foreach (string label in name.Split('.'))
            {
                buffer.Add((byte)label.Length);
                buffer.AddRange(Encoding.UTF8.GetBytes(label));
            }
        }
        buffer.Add(0);
    }

    /// <summary>Writes a value that is a single label even if it has a dot, such as a NetBIOS or site name.</summary>
    private static void WriteLabel(List<byte> buffer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length > 0)
        {
            buffer.Add((byte)bytes.Length);
            buffer.AddRange(bytes);
        }
        buffer.Add(0);
    }

    private enum LdapResultCode
    {
        Success = 0,
    }
}
