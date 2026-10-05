using System;
using System.Linq;
using System.Text;

namespace Obol;

/// <summary>A DNS query the DC locator DNS server of a <c>DcLocator</c> SSPI environment answered.</summary>
/// <remarks>
/// Raised by <see cref="ObolKdc.DnsRequestProcessed"/> of the KDC the query was sent to and output by
/// <c>Trace-ObolKdc</c>. The DNS server listens on UDP port 53 of the address of each KDC, a query is reported to
/// the KDC on the address it arrived on.
/// </remarks>
public sealed class ObolDnsEvent : ObolTraceEvent
{
    internal ObolDnsEvent(ObolKdc kdc, DcLocatorDnsExchange exchange)
        : base(kdc, exchange.Time, exchange.Duration, ObolKdcTransport.Udp, exchange.ClientAddress)
    {
        Id = exchange.Id;
        Name = exchange.Name;
        Type = exchange.Type;
        ResponseCode = exchange.ResponseCode;
        Answer = [.. exchange.Answers];
        Additional = [.. exchange.Additional];
        Exception = exchange.Exception;
        RequestBytes = exchange.RequestBytes;
        ReplyBytes = exchange.ReplyBytes;
        Message = BuildMessage();
    }

    /// <summary>
    /// A one line summary of the event: the query type and name and the response code with the answers, such as
    /// <c>SRV _kerberos._tcp.dc._msdcs.example.test: NoError, kdc1.example.test:88</c> or
    /// <c>A web.other.test: Refused</c>.
    /// </summary>
    public override string Message { get; }

    /// <summary>The ID of the query, null if it was too short to have a header.</summary>
    public ushort? Id { get; }

    /// <summary>The name asked for, null if the question could not be read.</summary>
    public string? Name { get; }

    /// <summary>The record type asked for, null if the question could not be read.</summary>
    public ObolDnsRecordType? Type { get; }

    /// <summary>The response code of the reply, null if the query was not answered.</summary>
    public ObolDnsResponseCode? ResponseCode { get; }

    /// <summary>The records in the answer section of the reply.</summary>
    public ObolDnsRecord[] Answer { get; }

    /// <summary>
    /// The records in the additional section of the reply, the addresses of the hosts of the SRV records.
    /// </summary>
    public ObolDnsRecord[] Additional { get; }

    /// <summary>The unexpected exception that dropped the query, otherwise null.</summary>
    public Exception? Exception { get; }

    /// <summary>The query as received.</summary>
    public byte[] RequestBytes { get; }

    /// <summary>The reply as sent, null if the query was not answered.</summary>
    public byte[]? ReplyBytes { get; }

    private string BuildMessage()
    {
        StringBuilder sb = new();
        if (Name is null)
        {
            sb.Append("DNS query");
        }
        else
        {
            sb.Append(Type?.ToString().ToUpperInvariant()).Append(' ').Append(Name);
        }
        sb.Append(": ");

        if (ResponseCode is not ObolDnsResponseCode responseCode)
        {
            sb.Append("no reply");
            if (Exception is not null)
            {
                sb.Append(", ").Append(Exception.Message);
            }
            return sb.ToString();
        }

        sb.Append(responseCode);
        if (responseCode == ObolDnsResponseCode.NoError)
        {
            sb.Append(", ").Append(Answer.Length == 0
                ? "no records"
                : string.Join(", ", Answer.Select(a => a.Value)));
        }
        return sb.ToString();
    }
}
