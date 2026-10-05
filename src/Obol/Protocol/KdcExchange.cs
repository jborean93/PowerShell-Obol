using System;
using System.Collections.Generic;
using System.Net;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Obol.Kerberos;
using EncryptionType = Obol.Kerberos.EncryptionType;
using MessageType = Obol.Kerberos.MessageType;
using PrincipalNameType = Obol.Kerberos.PrincipalNameType;

namespace Obol.Protocol;

/// <summary>A request to the KDC and the reply it sent, filled in as the request is processed.</summary>
/// <remarks>
/// The processor sets the Kerberos.NET objects it decoded, decrypted or built so far, so a request that fails part
/// way through still reports what the client asked for, and nothing is decrypted twice. The listener adds the
/// transport details. <see cref="ObolKdcEvent"/> is the public view, built from this with
/// <see cref="KdcMessageBuilder"/>.
/// </remarks>
internal sealed class KdcExchange
{
    private readonly List<ObolKeytabEntry> _keys = [];

    /// <summary>The local time the request was received.</summary>
    public DateTime Time { get; set; }

    /// <summary>How long processing the request took.</summary>
    public TimeSpan Duration { get; set; }

    /// <summary>The transport the request arrived on.</summary>
    public ObolKdcTransport Transport { get; set; }

    /// <summary>The address and port the request was sent from.</summary>
    public IPEndPoint? ClientAddress { get; set; }

    /// <summary>The request as received, without the TCP length prefix.</summary>
    public ReadOnlyMemory<byte> RequestBytes { get; set; }

    /// <summary>The reply as sent, without the TCP length prefix.</summary>
    public ReadOnlyMemory<byte> ReplyBytes { get; set; }

    /// <summary>The type the outer tag of the request claimed, Unknown if it was not a KDC request.</summary>
    public MessageType RequestType { get; set; }

    /// <summary>The error sent, or KDC_ERR_NONE for a reply with a ticket.</summary>
    public ErrorCode ErrorCode { get; set; } = ErrorCode.None;

    /// <summary>The e-text of the error sent, if any.</summary>
    public string? ErrorText { get; set; }

    /// <summary>The unexpected exception that was answered with KRB_ERR_GENERIC, if any.</summary>
    public Exception? Exception { get; set; }

    /// <summary>The client name with its realm, from the request or the TGT of a TGS-REQ.</summary>
    public string? ClientName { get; set; }

    /// <summary>The service name with its realm as the client sent it.</summary>
    public string? ServiceName { get; set; }

    /// <summary>The decoded request, null if it did not decode.</summary>
    public KrbKdcReq? Request { get; set; }

    /// <summary>The AP-REQ of the PA-TGS-REQ of a TGS-REQ, once decoded.</summary>
    public KrbApReq? ApReq { get; set; }

    /// <summary>The PA-TGS-REQ value, the AP-REQ as sent.</summary>
    public ReadOnlyMemory<byte> ApReqBytes { get; set; }

    /// <summary>The decrypted TGT of a TGS-REQ, once decrypted.</summary>
    public KrbEncTicketPart? Tgt { get; set; }

    /// <summary>The decrypted authenticator of a TGS-REQ, once decrypted.</summary>
    public KrbAuthenticator? Authenticator { get; set; }

    /// <summary>The decrypted PA-ENC-TIMESTAMP of an AS-REQ, once decrypted.</summary>
    public KrbPaEncTsEnc? Timestamp { get; set; }

    /// <summary>The reply with a ticket, if one was sent.</summary>
    public KrbKdcRep? Reply { get; set; }

    /// <summary>The plaintext of the ticket in <see cref="Reply"/>.</summary>
    public KrbEncTicketPart? IssuedTicketPart { get; set; }

    /// <summary>The plaintext of the enc-part of <see cref="Reply"/>.</summary>
    public KrbEncKdcRepPart? ReplyPart { get; set; }

    /// <summary>The KRB-ERROR sent, if the request was not answered with a ticket.</summary>
    public KrbError? Error { get; set; }

    /// <summary>The long-term keys used to process the request, see <see cref="AddKey"/>.</summary>
    public IReadOnlyList<ObolKeytabEntry> Keys => _keys;

    /// <summary>Records a long-term key of a principal that was used for the request.</summary>
    /// <remarks>
    /// Every encrypted part of an exchange is under a long-term key or a key found by decrypting with one, so
    /// these keys decrypt the request and reply even after the principal's keys change.
    /// </remarks>
    public void AddKey(KdcPrincipal principal, KerberosKey key)
    {
        ObolPrincipal p = principal.Principal;
        foreach (ObolKeytabEntry existing in _keys)
        {
            if (existing.Realm == p.Realm
                && existing.Name == p.Name
                && existing.Kvno == principal.State.Kvno
                && (int)existing.EncryptionType == (int)key.EncryptionType)
            {
                return;
            }
        }

        _keys.Add(new ObolKeytabEntry(
            p.Realm,
            p.Components,
            PrincipalNameType.Principal,
            DateTime.UtcNow,
            principal.State.Kvno,
            (EncryptionType)key.EncryptionType,
            key.GetKey().ToArray()));
    }

    /// <summary>Records the error sent instead of a ticket.</summary>
    public void SetError(KrbError error, ReadOnlyMemory<byte> bytes)
    {
        Error = error;
        ErrorCode = error.ErrorCode.ToObol();
        ErrorText = error.EText;
        ReplyBytes = bytes;
        Reply = null;
        IssuedTicketPart = null;
        ReplyPart = null;
    }
}
