using System;
using System.Text;
using Obol.Kerberos;
using Obol.Protocol;

namespace Obol;

/// <summary>A request an <see cref="ObolKdc"/> answered and the reply it sent.</summary>
/// <remarks>
/// Raised by <see cref="ObolKdc.RequestProcessed"/> and output by <c>Trace-ObolKdc</c>, with
/// <c>Register-ObjectEvent</c> it is <c>$Event.SourceEventArgs</c>. The event holds the facts of the exchange and
/// the two messages decoded as far as the KDC got: a rejected request still shows what the client asked for, and the
/// parts the KDC decrypted or built, such as the TGT of a TGS-REQ and the ticket issued, are decrypted in the model.
/// <see cref="Key"/> holds the long-term keys that decrypt every encrypted part of both messages.
/// </remarks>
public sealed class ObolKdcEvent : ObolTraceEvent
{
    internal ObolKdcEvent(ObolKdc kdc, KdcExchange exchange)
        : base(kdc, exchange.Time, exchange.Duration, exchange.Transport, exchange.ClientAddress)
    {
        ClientName = exchange.ClientName;
        ServiceName = exchange.ServiceName;
        ErrorCode = exchange.ErrorCode;
        Exception = exchange.Exception;
        Key = [.. exchange.Keys];
        Request = KdcMessageBuilder.BuildRequest(exchange);
        Reply = KdcMessageBuilder.BuildReply(exchange);
        Message = BuildMessage();
    }

    /// <summary>
    /// A one line summary of the event: the request type, the client and service, and the reply with the ticket's
    /// encryption types and flags or the error code and text, such as
    /// <c>AS-REQ user@EXAMPLE.TEST -&gt; krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: AS-REP, Aes256Sha1 ticket and session
    /// key, PreAuthenticated, Initial</c> or <c>AS-REQ user@EXAMPLE.TEST -&gt; krbtgt/EXAMPLE.TEST@EXAMPLE.TEST:
    /// PreAuthRequired</c>.
    /// </summary>
    public override string Message { get; }

    /// <summary>
    /// The client principal with its realm, such as <c>user@EXAMPLE.TEST</c>, as the client sent it in an AS-REQ or
    /// from the TGT of a TGS-REQ. Null if the request had none or was not decoded that far.
    /// </summary>
    public string? ClientName { get; }

    /// <summary>
    /// The service principal with its realm as the client sent it, such as <c>krbtgt/EXAMPLE.TEST@EXAMPLE.TEST</c>
    /// for a TGT. Null if the request was not decoded.
    /// </summary>
    public string? ServiceName { get; }

    /// <summary>
    /// <c>None</c> if a ticket was issued, otherwise the error-code of the KRB-ERROR sent, which is
    /// <see cref="Reply"/>.
    /// </summary>
    public ErrorCode ErrorCode { get; }

    /// <summary>
    /// The unexpected exception that was answered with <see cref="ErrorCode.Generic"/>, such as a
    /// request that is not valid DER. Null for a request the KDC rejected on purpose.
    /// </summary>
    public Exception? Exception { get; }

    /// <summary>
    /// The long-term keys used for the request, as keytab entries: the client's key an AS-REP is encrypted with, the
    /// krbtgt key of the TGT in a TGS-REQ and the service key the ticket is encrypted with. The keys found by
    /// decrypting with these, such as the TGT session key and the authenticator subkey, decrypt the rest.
    /// </summary>
    public ObolKeytabEntry[] Key { get; }

    /// <summary>
    /// The request as received: an <see cref="KdcRequest"/> for an AS-REQ, an <see cref="TgsRequest"/> for
    /// a TGS-REQ, or a plain <see cref="Message"/> with the bytes if it could not be decoded.
    /// </summary>
    public Message Request { get; }

    /// <summary>
    /// The reply as sent: an <see cref="KdcReply"/> with the ticket, or an <see cref="ErrorReply"/>.
    /// </summary>
    public Message Reply { get; }

    private string BuildMessage()
    {
        StringBuilder sb = new();
        sb.Append(Request.MessageType switch
        {
            MessageType.AsReq => "AS-REQ",
            MessageType.TgsReq => "TGS-REQ",
            _ => "Unknown request",
        });
        if (ClientName is not null)
        {
            sb.Append(' ').Append(ClientName);
        }
        if (ServiceName is not null)
        {
            sb.Append(" -> ").Append(ServiceName);
        }
        sb.Append(": ");

        if (Reply is not KdcReply reply)
        {
            sb.Append(Reply);
            return sb.ToString();
        }

        sb.Append(reply.MessageType == MessageType.AsRep ? "AS-REP" : "TGS-REP");
        EncryptionType ticketType = reply.Ticket.EncryptedPart.EncryptionType;
        if (reply.Ticket.DecryptedPart is not TicketPart ticket)
        {
            sb.Append(", ").Append(ticketType).Append(" ticket");
            return sb.ToString();
        }

        EncryptionType sessionType = ticket.Key.EncryptionType;
        if (ticketType == sessionType)
        {
            sb.Append(", ").Append(ticketType).Append(" ticket and session key");
        }
        else
        {
            sb.Append(", ").Append(ticketType).Append(" ticket, ").Append(sessionType).Append(" session key");
        }
        if (ticket.Flag != TicketFlag.None)
        {
            sb.Append(", ").Append(ticket.Flag);
        }
        if (ticket.Pac is null)
        {
            sb.Append(", no PAC");
        }
        return sb.ToString();
    }
}
