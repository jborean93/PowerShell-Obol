using System;
using System.Collections.Generic;
using System.Linq;
using Kerberos.NET.Entities;
using Obol.Kerberos;
using AuthorizationDataType = Obol.Kerberos.AuthorizationDataType;
using KerberosPrincipalName = Obol.Kerberos.PrincipalName;
using MessageType = Obol.Kerberos.MessageType;
using PrincipalNameType = Obol.Kerberos.PrincipalNameType;

namespace Obol.Protocol;

/// <summary>
/// Builds the public message objects of an <see cref="ObolKdcEvent"/> from the Kerberos.NET objects a
/// <see cref="KdcExchange"/> holds. Only the parts the processor decrypted are decrypted here, the rest is decoded.
/// </summary>
internal static class KdcMessageBuilder
{
    /// <summary>Builds the request, a plain message with the claimed type if it did not decode.</summary>
    public static Message BuildRequest(KdcExchange exchange)
    {
        byte[] bytes = exchange.RequestBytes.ToArray();
        if (exchange.Request is not KrbKdcReq request)
        {
            return new Message(exchange.RequestType, bytes);
        }

        ApRequest? apRequest = exchange.ApReq is KrbApReq apReq
            ? BuildApRequest(apReq, exchange.ApReqBytes.ToArray(), exchange.Tgt, exchange.Authenticator)
            : null;
        PreAuthData[] preAuthData = BuildPreAuthData(request.PaData, apRequest, exchange.Timestamp);
        KdcRequestBody body = BuildBody(request.Body);

        return request is KrbTgsReq
            ? new TgsRequest(bytes)
            {
                ProtocolVersion = request.ProtocolVersionNumber,
                PreAuthData = preAuthData,
                Body = body,
                ApRequest = apRequest,
            }
            : new KdcRequest(MessageType.AsReq, bytes)
            {
                ProtocolVersion = request.ProtocolVersionNumber,
                PreAuthData = preAuthData,
                Body = body,
            };
    }

    /// <summary>Builds the reply, a KRB-ERROR or a KDC-REP.</summary>
    public static Message BuildReply(KdcExchange exchange)
    {
        byte[] bytes = exchange.ReplyBytes.ToArray();
        if (exchange.Error is KrbError error)
        {
            return BuildError(error, bytes);
        }
        if (exchange.Reply is not KrbKdcRep reply)
        {
            return new Message(MessageType.Unknown, bytes);
        }

        return new KdcReply(reply.MessageType.ToObol(), bytes)
        {
            ProtocolVersion = reply.ProtocolVersionNumber,
            PreAuthData = BuildPreAuthData(reply.PaData, null, null),
            ClientName = Name(reply.CName, reply.CRealm),
            Ticket = BuildTicket(reply.Ticket, exchange.IssuedTicketPart),
            EncryptedPart = Encrypted(reply.EncryptedPart),
            DecryptedPart = exchange.ReplyPart is KrbEncKdcRepPart part ? BuildReplyPart(part) : null,
        };
    }

    private static ErrorReply BuildError(KrbError error, byte[] bytes)
    {
        PreAuthData[]? methodData = null;
        if (error.EData is ReadOnlyMemory<byte> data)
        {
            try
            {
                methodData = BuildPreAuthData(KrbMethodData.Decode(data).MethodData, null, null);
            }
            catch (Exception)
            {
                // The e-data is something else, such as KERB-ERROR-DATA.
            }
        }

        return new ErrorReply(bytes)
        {
            ProtocolVersion = error.ProtocolVersionNumber,
            ClientTime = error.CTime is DateTimeOffset ctime ? Local(ctime, error.Cusec) : null,
            ServerTime = Local(error.STime, error.Susc),
            ErrorCode = error.ErrorCode.ToObol(),
            ClientName = error.CName is null ? null : Name(error.CName, error.CRealm ?? ""),
            ServiceName = Name(error.SName, error.Realm),
            ErrorText = error.EText,
            ErrorData = error.EData?.ToArray(),
            MethodData = methodData,
        };
    }

    private static KdcRequestBody BuildBody(KrbKdcReqBody body) => new()
    {
        KdcOption = body.KdcOptions.ToObol(),
        ClientName = body.CName is null ? null : Name(body.CName, body.Realm),
        Realm = body.Realm ?? "",
        ServiceName = body.SName is null ? null : Name(body.SName, body.Realm),
        From = body.From?.LocalDateTime,
        Till = body.Till.LocalDateTime,
        RenewTill = body.RTime?.LocalDateTime,
        Nonce = body.Nonce,
        EncryptionType = [.. (body.EType ?? []).Select(e => e.ToObol())],
        Address = Addresses(body.Addresses),
        EncryptedAuthorizationData = body.EncAuthorizationData is null ? null : Encrypted(body.EncAuthorizationData),
        AdditionalTicket = [.. (body.AdditionalTickets ?? []).Select(t => BuildTicket(t, null))],
    };

    /// <summary>Builds the PA-DATA list, the known types decoded when they parse.</summary>
    /// <param name="paData"></param>
    /// <param name="apRequest">The already built AP-REQ for a PA-TGS-REQ element.</param>
    /// <param name="timestamp">The decrypted timestamp for a PA-ENC-TIMESTAMP element.</param>
    private static PreAuthData[] BuildPreAuthData(
        KrbPaData[]? paData,
        ApRequest? apRequest,
        KrbPaEncTsEnc? timestamp)
    {
        List<PreAuthData> result = [];
        foreach (KrbPaData pa in paData ?? [])
        {
            byte[] value = pa.Value.ToArray();
            PreAuthData? decoded = null;
            try
            {
                decoded = pa.Type.ToObol() switch
                {
                    PreAuthDataType.TgsReq when apRequest is not null => new TgsRequestPreAuthData(value, apRequest),
                    PreAuthDataType.EncTimestamp => new TimestampPreAuthData(
                        value,
                        Encrypted(KrbEncryptedData.Decode(pa.Value)),
                        timestamp is null ? null : Local(timestamp.PaTimestamp, timestamp.PaUSec)),
                    PreAuthDataType.ETypeInfo2 => new ETypeInfo2PreAuthData(
                        value,
                        [.. (KrbETypeInfo2.Decode(pa.Value).ETypeInfo ?? []).Select(e => new ETypeInfo2Entry(
                            e.EType.ToObol(), e.Salt, e.S2kParams?.ToArray()))]),
                    PreAuthDataType.PacRequest => new PacRequestPreAuthData(
                        value,
                        KrbPaPacRequest.Decode(pa.Value).IncludePac),
                    _ => null,
                };
            }
            catch (Exception)
            {
                // A value that does not parse is still listed with its bytes.
            }

            result.Add(decoded ?? new PreAuthData(pa.Type.ToObol(), value));
        }

        return [.. result];
    }

    private static ApRequest BuildApRequest(
        KrbApReq apReq,
        byte[] bytes,
        KrbEncTicketPart? ticketPart,
        KrbAuthenticator? authenticator) => new(bytes)
        {
            ProtocolVersion = apReq.ProtocolVersionNumber,
            ApOption = apReq.ApOptions.ToObol(),
            Ticket = BuildTicket(apReq.Ticket, ticketPart),
            EncryptedAuthenticator = Encrypted(apReq.Authenticator),
            Authenticator = authenticator is null ? null : BuildAuthenticator(authenticator),
        };

    private static Ticket BuildTicket(KrbTicket ticket, KrbEncTicketPart? part) => new()
    {
        Version = ticket.TicketNumber,
        Realm = ticket.Realm ?? "",
        ServiceName = Name(ticket.SName, ticket.Realm),
        EncryptedPart = Encrypted(ticket.EncryptedPart),
        DecryptedPart = part is null ? null : BuildTicketPart(part),
    };

    private static TicketPart BuildTicketPart(KrbEncTicketPart part)
    {
        AuthorizationData[] authorizationData = BuildAuthorizationData(part.AuthorizationData);
        return new TicketPart
        {
            Flag = part.Flags.ToObol(),
            Key = Key(part.Key),
            ClientName = Name(part.CName, part.CRealm),
            TransitedType = (int)(part.Transited?.Type ?? 0),
            Transited = part.Transited?.Contents.ToArray() ?? [],
            AuthTime = part.AuthTime.LocalDateTime,
            StartTime = part.StartTime?.LocalDateTime,
            EndTime = part.EndTime.LocalDateTime,
            RenewTill = part.RenewTill?.LocalDateTime,
            Address = Addresses(part.CAddr),
            AuthorizationData = authorizationData,
            Pac = FindPac(authorizationData),
        };
    }

    private static Authenticator BuildAuthenticator(KrbAuthenticator authenticator) => new()
    {
        Version = authenticator.AuthenticatorVersionNumber,
        ClientName = Name(authenticator.CName, authenticator.CRealm),
        Checksum = authenticator.Checksum is KrbChecksum checksum
            ? new Checksum(checksum.Type.ToObol(), checksum.Checksum.ToArray())
            : null,
        Time = Local(authenticator.CTime, authenticator.CuSec),
        Subkey = authenticator.Subkey is KrbEncryptionKey subkey ? Key(subkey) : null,
        SequenceNumber = authenticator.SequenceNumber,
        AuthorizationData = BuildAuthorizationData(authenticator.AuthorizationData),
    };

    private static KdcReplyPart BuildReplyPart(KrbEncKdcRepPart part) => new()
    {
        Key = Key(part.Key),
        LastRequest = [.. (part.LastReq ?? []).Select(l => new LastRequest(l.Type, l.Value.LocalDateTime))],
        Nonce = part.Nonce,
        KeyExpiration = part.KeyExpiration?.LocalDateTime,
        Flag = part.Flags.ToObol(),
        AuthTime = part.AuthTime.LocalDateTime,
        StartTime = part.StartTime?.LocalDateTime,
        EndTime = part.EndTime.LocalDateTime,
        RenewTill = part.RenewTill?.LocalDateTime,
        ServiceName = Name(part.SName, part.Realm),
        Address = Addresses(part.CAddr),
        EncryptedPreAuthData = BuildPreAuthData(part.EncryptedPaData?.MethodData, null, null),
    };

    /// <summary>Builds the authorization data, AD-IF-RELEVANT and the PAC decoded when they parse.</summary>
    private static AuthorizationData[] BuildAuthorizationData(KrbAuthorizationData[]? authorizationData)
    {
        List<AuthorizationData> result = [];
        foreach (KrbAuthorizationData ad in authorizationData ?? [])
        {
            byte[] data = ad.Data.ToArray();
            AuthorizationData? decoded = null;
            try
            {
                decoded = ad.Type.ToObol() switch
                {
                    AuthorizationDataType.IfRelevant => new IfRelevantAuthorizationData(
                        data,
                        BuildAuthorizationData(KrbAuthorizationDataSequence.Decode(ad.Data).AuthorizationData)),
                    AuthorizationDataType.Win2kPac => new PacAuthorizationData(data, PacBuilder.Build(ad.Data)),
                    _ => null,
                };
            }
            catch (Exception)
            {
                // Data that does not parse is still listed with its bytes.
            }

            result.Add(decoded ?? new AuthorizationData(ad.Type.ToObol(), data));
        }

        return [.. result];
    }

    private static Pac? FindPac(AuthorizationData[] authorizationData)
    {
        foreach (AuthorizationData ad in authorizationData)
        {
            Pac? pac = ad switch
            {
                PacAuthorizationData pacData => pacData.Pac,
                IfRelevantAuthorizationData ifRelevant => FindPac(ifRelevant.Element),
                _ => null,
            };
            if (pac is not null)
            {
                return pac;
            }
        }
        return null;
    }

    private static KerberosPrincipalName Name(KrbPrincipalName? name, string? realm)
        => new(name?.Type.ToObol() ?? PrincipalNameType.Unknown, name?.Name ?? [], realm ?? "");

    private static EncryptedData Encrypted(KrbEncryptedData data)
        => new(data.EType.ToObol(), data.KeyVersionNumber, data.Cipher.ToArray());

    private static EncryptionKey Key(KrbEncryptionKey key) => new(key.EType.ToObol(), key.KeyValue.ToArray());

    private static HostAddress[] Addresses(KrbHostAddress[]? addresses)
        => [.. (addresses ?? []).Select(a => new HostAddress(a.AddressType.ToObol(), a.Address.ToArray()))];

    /// <summary>A Kerberos time with its microseconds as local time.</summary>
    private static DateTime Local(DateTimeOffset time, int? microseconds)
        => time.AddTicks((microseconds ?? 0) * 10L).LocalDateTime;
}
