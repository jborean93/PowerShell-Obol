using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace Obol;

/// <summary>An LDAP ping the DC locator CLDAP responder of a <c>DcLocator</c> SSPI environment answered.</summary>
/// <remarks>
/// Raised by <see cref="ObolKdc.LdapRequestProcessed"/> of the KDC the ping was sent to and output by
/// <c>Trace-ObolKdc</c>. The Windows DC locator sends the ping, an LDAP search over UDP port 389 for the
/// <c>Netlogon</c> attribute, to the KDC it found through DNS to check it is a domain controller of the domain, see
/// MS-ADTS 6.3.3. The responder listens on UDP port 389 of the address of each KDC, a ping is reported to the KDC on
/// the address it arrived on.
/// </remarks>
public sealed class ObolLdapEvent : ObolTraceEvent
{
    internal ObolLdapEvent(ObolKdc kdc, DcLocatorLdapExchange exchange)
        : base(kdc, exchange.Time, exchange.Duration, ObolKdcTransport.Udp, exchange.ClientAddress)
    {
        MessageId = exchange.MessageId;
        IsPing = exchange.IsSearch;
        Filter = new Dictionary<string, byte[]>(exchange.Filter, StringComparer.OrdinalIgnoreCase);
        DnsDomain = GetString("DnsDomain");
        Host = GetString("Host");
        User = GetString("User");
        DomainGuid = Filter.TryGetValue("DomainGuid", out byte[]? guid) && guid.Length == 16 ? new Guid(guid) : null;
        NtVersion = GetUInt32("NtVer") is uint ntVer ? (ObolNetlogonNtVersion)ntVer : null;
        AccountControl = GetUInt32("AAC");
        DcHostName = exchange.DcHostName;
        DcAddress = exchange.DcAddress;
        DcFlags = (ObolSspiDcFlags)exchange.DcFlags;
        Exception = exchange.Exception;
        RequestBytes = exchange.RequestBytes;
        ReplyBytes = exchange.ReplyBytes;
        Message = BuildMessage();
    }

    /// <summary>
    /// A one line summary of the event: the domain of the ping with its NtVer flags, and the KDC in the reply, such
    /// as <c>LDAP ping example.test (V5Ex, V5ExWithIp): kdc1.example.test 127.0.0.2</c> or
    /// <c>LDAP ping other.test (V5Ex): no such domain</c>.
    /// </summary>
    public override string Message { get; }

    /// <summary>The LDAP message ID, null if the request was not decoded that far.</summary>
    public int? MessageId { get; }

    /// <summary>Whether the request is an LDAP search, the form of a ping. Anything else is not answered.</summary>
    public bool IsPing { get; }

    /// <summary>
    /// Every equality match of the search filter, such as <c>DnsDomain</c>, <c>Host</c> and <c>NtVer</c>, with the
    /// value as sent. The names are case insensitive.
    /// </summary>
    public IReadOnlyDictionary<string, byte[]> Filter { get; }

    /// <summary>The <c>DnsDomain</c> of the ping, the domain the locator looks for a DC of.</summary>
    public string? DnsDomain { get; }

    /// <summary>The <c>Host</c> of the ping, the NetBIOS name of the client.</summary>
    public string? Host { get; }

    /// <summary>The <c>User</c> of the ping, the account the locator checks the DC has.</summary>
    public string? User { get; }

    /// <summary>The <c>DomainGuid</c> of the ping.</summary>
    public Guid? DomainGuid { get; }

    /// <summary>The <c>NtVer</c> of the ping, the form of reply the client asks for.</summary>
    public ObolNetlogonNtVersion? NtVersion { get; }

    /// <summary>The <c>AAC</c> of the ping, the account control bits the account must have.</summary>
    public uint? AccountControl { get; }

    /// <summary>
    /// The host name of the KDC in the reply, null if the reply has no NETLOGON_SAM_LOGON_RESPONSE_EX, which the
    /// locator treats as the host not being a DC of the domain.
    /// </summary>
    public string? DcHostName { get; }

    /// <summary>The address of the KDC in the reply.</summary>
    public IPAddress? DcAddress { get; }

    /// <summary>The DC flags in the reply, <c>None</c> if the reply has no NETLOGON_SAM_LOGON_RESPONSE_EX.</summary>
    public ObolSspiDcFlags DcFlags { get; }

    /// <summary>
    /// The exception that stopped the request from being answered, such as a request that is not valid BER, otherwise
    /// null.
    /// </summary>
    public Exception? Exception { get; }

    /// <summary>The request as received.</summary>
    public byte[] RequestBytes { get; }

    /// <summary>The reply as sent, null if the request was not answered.</summary>
    public byte[]? ReplyBytes { get; }

    private string? GetString(string name)
        => Filter.TryGetValue(name, out byte[]? value) ? Encoding.UTF8.GetString(value) : null;

    private uint? GetUInt32(string name)
        => Filter.TryGetValue(name, out byte[]? value) && value.Length >= 4
            ? BinaryPrimitives.ReadUInt32LittleEndian(value)
            : null;

    private string BuildMessage()
    {
        StringBuilder sb = new();
        if (!IsPing)
        {
            sb.Append("LDAP request: not an LDAP ping, no reply");
            if (Exception is not null)
            {
                sb.Append(", ").Append(Exception.Message);
            }
            return sb.ToString();
        }

        sb.Append("LDAP ping ").Append(DnsDomain ?? "without DnsDomain");
        if (NtVersion is ObolNetlogonNtVersion ntVersion)
        {
            sb.Append(" (").Append(ntVersion).Append(')');
        }
        sb.Append(": ");

        if (ReplyBytes is null)
        {
            sb.Append("no reply");
            if (Exception is not null)
            {
                sb.Append(", ").Append(Exception.Message);
            }
        }
        else if (DcHostName is null)
        {
            sb.Append("no such domain");
        }
        else
        {
            sb.Append(DcHostName).Append(' ').Append(DcAddress);
        }
        return sb.ToString();
    }
}
