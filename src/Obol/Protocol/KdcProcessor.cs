using System;
using System.Formats.Asn1;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Obol.Kerberos;
using AuthorizationDataType = Obol.Kerberos.AuthorizationDataType;
using ChecksumType = Obol.Kerberos.ChecksumType;
using EncryptionType = Obol.Kerberos.EncryptionType;
using KeyUsage = Obol.Kerberos.KeyUsage;
using KrbEncryptionType = Kerberos.NET.Crypto.EncryptionType;
using KrbPacClientInfo = Kerberos.NET.Entities.PacClientInfo;
using MessageType = Obol.Kerberos.MessageType;
using PrincipalNameType = Obol.Kerberos.PrincipalNameType;

namespace Obol.Protocol;

/// <summary>Processes the AS-REQ and TGS-REQ messages for the realm of a principal store.</summary>
/// <remarks>
/// Kerberos.NET is used to encode and decode the messages, for the cryptography and to build the PAC. The KDC logic
/// is done here as the Kerberos.NET KDC handlers issue tickets with flags and times the client did not ask for, do
/// not support renewing tickets, pick session keys the service may not support and do not check the checksum of the
/// TGS-REQ body.
/// </remarks>
internal sealed class KdcProcessor
{
    /// <summary>The application tags of the request messages, the values of their message types.</summary>
    private const int AsReqTag = (int)MessageType.AsReq;
    private const int TgsReqTag = (int)MessageType.TgsReq;

    /// <summary>The RFC 3961 checksum types that are not keyed, other than RSA-MD5 which Windows sends.</summary>
    private static readonly ChecksumType[] s_unkeyedChecksumTypes =
    [
        ChecksumType.Crc32,
        ChecksumType.RsaMd4,
        ChecksumType.Sha1,
    ];

    private readonly PrincipalStore _store;
    private readonly TimeProvider _time;
    private readonly KrbPrincipalName _krbtgtName;

    /// <param name="store">The principals of the realm.</param>
    /// <param name="time">The clock, the system clock if not set.</param>
    public KdcProcessor(PrincipalStore store, TimeProvider? time = null)
    {
        _store = store;
        _time = time ?? TimeProvider.System;
        _krbtgtName = KrbPrincipalName.WellKnown.Krbtgt(store.Realm);
    }

    /// <summary>The realm served.</summary>
    public string Realm => _store.Realm;

    /// <summary>Processes a request, a failure is returned as a KRB-ERROR so there is always a reply.</summary>
    /// <returns>The exchange with the reply and what was decoded and decided while processing the request.</returns>
    public KdcExchange Process(ReadOnlyMemory<byte> request)
    {
        KdcExchange exchange = new() { RequestBytes = request };
        try
        {
            Asn1Tag tag = new AsnReader(request, AsnEncodingRules.DER).PeekTag();
            if (tag.TagClass == TagClass.Application && tag.TagValue == AsReqTag)
            {
                exchange.RequestType = MessageType.AsReq;
                exchange.ReplyBytes = ProcessAsReq(request, exchange);
            }
            else if (tag.TagClass == TagClass.Application && tag.TagValue == TgsReqTag)
            {
                exchange.RequestType = MessageType.TgsReq;
                exchange.ReplyBytes = ProcessTgsReq(request, exchange);
            }
            else
            {
                throw new KdcException(ErrorCode.Generic,
                    $"Failed to process request: the message type {tag} is not supported");
            }
        }
        catch (KdcException e)
        {
            SetError(exchange, e.Code, e.Text, e.SName, e.ErrorData);
        }
        catch (Exception e)
        {
            // Such as a request that is not valid DER or misses a required field.
            exchange.Exception = e;
            SetError(exchange, ErrorCode.Generic, $"Failed to process request: {e.Message}");
        }

        return exchange;
    }

    /// <summary>Creates the exchange with the KRB_ERR_FIELD_TOOLONG error for a TCP request too long to read.</summary>
    public KdcExchange CreateRequestTooLongExchange(string text)
    {
        KdcExchange exchange = new();
        SetError(exchange, ErrorCode.FieldTooLong, text);
        return exchange;
    }

    /// <summary>Replaces the reply of an exchange with KRB_ERR_RESPONSE_TOO_BIG as it is too big for UDP.</summary>
    public void ReplaceResponseTooBig(KdcExchange exchange, string text)
        => SetError(exchange, ErrorCode.ResponseTooBig, text);

    /// <summary>Records a KRB-ERROR as the reply of the exchange.</summary>
    private void SetError(
        KdcExchange exchange,
        ErrorCode code,
        string? text,
        KrbPrincipalName? sname = null,
        ReadOnlyMemory<byte>? errorData = null)
    {
        KrbError error = CreateError(code, text, sname, errorData);
        exchange.SetError(error, error.EncodeApplication());
    }

    /// <summary>Creates a KRB-ERROR from the KDC.</summary>
    /// <param name="code">The error code.</param>
    /// <param name="text">The e-text, if any.</param>
    /// <param name="sname">The sname, the krbtgt of the realm if not set.</param>
    /// <param name="errorData">The e-data, if any.</param>
    private KrbError CreateError(
        ErrorCode code,
        string? text,
        KrbPrincipalName? sname = null,
        ReadOnlyMemory<byte>? errorData = null)
    {
        KrbError error = new()
        {
            ErrorCode = code.ToKerberosNet(),
            EText = text,
            Realm = Realm,
            SName = sname ?? _krbtgtName,
            EData = errorData,
        };

        // Not KrbError.StampServerTime(), it puts the microseconds in cusec and leaves susec 0 (Kerberos.NET 4.6).
        DateTimeOffset now = _time.GetUtcNow();
        long subSecondTicks = now.Ticks % TimeSpan.TicksPerSecond;
        error.STime = now.AddTicks(-subSecondTicks);
        error.Susc = (int)(subSecondTicks / TimeSpan.TicksPerMicrosecond);

        return error;
    }

    private ReadOnlyMemory<byte> ProcessAsReq(ReadOnlyMemory<byte> message, KdcExchange exchange)
    {
        KrbAsReq asReq = KrbAsReq.DecodeApplication(message);
        exchange.Request = asReq;
        KrbKdcReqBody body = asReq.Body;
        RecordRequest(exchange, body);
        exchange.ClientName = FormatName(body.CName, body.Realm);
        CheckRequest(asReq.ProtocolVersionNumber, body.Realm);

        KdcPrincipal client = FindPrincipal(body.CName)
            ?? throw new KdcException(ErrorCode.ClientPrincipalUnknown);

        // An AS-REQ is usually for the krbtgt but can be for any service, like kadmin/changepw.
        KdcPrincipal service = FindPrincipal(body.SName)
            ?? throw new KdcException(ErrorCode.ServicePrincipalUnknown, sname: body.SName);

        DateTimeOffset now = _time.GetUtcNow();
        KdcOption options = body.KdcOptions.ToObol();
        EncryptionType[] requestedETypes = ToObol(body.EType);
        bool preauthenticated = false;
        KerberosKey replyKey;
        KrbPaData? timestamp = FindPaData(asReq, PreAuthDataType.EncTimestamp);
        if (timestamp is not null)
        {
            // A timestamp is checked even if the principal does not require pre-auth, like the MIT KDC.
            replyKey = ValidateTimestamp(timestamp, client, now, exchange);
            preauthenticated = true;
        }
        else
        {
            // Without pre-auth the reply is encrypted with the client's preferred key it has.
            replyKey = requestedETypes
                .Select(client.GetKey)
                .FirstOrDefault(k => k is not null)
                ?? throw new KdcException(ErrorCode.EncryptionTypeNotSupported,
                    "The client has no key for any of the requested encryption types");

            if (!client.State.Flags.HasFlag(PacUserAccountControl.DontRequirePreAuth))
            {
                KrbMethodData methodData = new()
                {
                    MethodData =
                    [
                        new KrbPaData { Type = PreAuthDataType.EncTimestamp.ToKerberosNet() },
                        CreateETypeInfo2(client, requestedETypes),
                    ],
                };
                throw new KdcException(ErrorCode.PreAuthRequired, errorData: methodData.Encode());
            }
        }
        exchange.AddKey(client, replyKey);
        exchange.AddKey(service, service.PreferredKey);

        EncryptionType sessionEType = TicketPolicy.SelectSessionKeyType(requestedETypes, service)
            ?? throw new KdcException(ErrorCode.EncryptionTypeNotSupported,
                "The service has no key for any of the requested encryption types");

        // Only the options the client asked for are granted, RFC 4120 3.1.3.
        TicketFlag flags = TicketFlag.Initial;
        if (preauthenticated)
        {
            flags |= TicketFlag.PreAuthenticated;
        }
        // MS-SAMR USER_NOT_DELEGATED the ticket is not forwardable even if requested.
        if (options.HasFlag(KdcOption.Forwardable)
            && !client.State.Flags.HasFlag(PacUserAccountControl.NotDelegated))
        {
            flags |= TicketFlag.Forwardable;
        }
        if (service.State.Flags.HasFlag(PacUserAccountControl.TrustedForDelegation))
        {
            flags |= TicketFlag.OkAsDelegate;
        }

        TicketTimes times = TicketPolicy.Compute(body, now, ref flags, maxEndTime: null, maxRenewTill: null);

        return IssueTicket(new TicketRequest
        {
            IsAsReq = true,
            Client = client,
            // Obol does not canonicalize names, RFC 6806 6. lets the KDC reply with the requested name.
            ClientName = body.CName!,
            ServiceName = body.SName!,
            ServiceKey = service.PreferredKey,
            SessionEType = sessionEType,
            Flags = flags,
            Times = times,
            AuthTime = now,
            Now = now,
            Addresses = body.Addresses,
            Nonce = body.Nonce,
            SupportedEncryptionTypes = service.EncodeSupportedEncryptionTypes(),
            // Like AD the PAC is included unless the client asks for it not to be or the service does not want one.
            IncludePac = (GetPacRequest(asReq) ?? true) && TakesPac(service),
            ReplyKey = replyKey,
            ReplyKeyUsage = KeyUsage.AsRepEncryptedPart,
            // The salt used for the reply key, the client uses it instead of the default salt of the name it sent
            // which differs for an alias.
            PaData = [CreateETypeInfo2(client, [replyKey.EncryptionType.ToObol()])],
        }, exchange);
    }

    private ReadOnlyMemory<byte> ProcessTgsReq(ReadOnlyMemory<byte> message, KdcExchange exchange)
    {
        KrbTgsReq tgsReq = KrbTgsReq.DecodeApplication(message);
        exchange.Request = tgsReq;
        KrbKdcReqBody body = tgsReq.Body;
        RecordRequest(exchange, body);
        CheckRequest(tgsReq.ProtocolVersionNumber, body.Realm);

        DateTimeOffset now = _time.GetUtcNow();
        KdcOption options = body.KdcOptions.ToObol();
        EncryptionType[] requestedETypes = ToObol(body.EType);
        KdcPrincipal krbtgt = new(_store.Krbtgt);
        (KrbEncTicketPart tgt, KrbAuthenticator authenticator) = ValidateTgsAuthentication(
            tgsReq, message, krbtgt, now, exchange);
        exchange.ClientName = FormatName(tgt.CName, tgt.CRealm);
        TicketFlag tgtFlags = tgt.Flags.ToObol();

        // RFC 4120 3.3.3. the client name is copied from the TGT, the client must still exist for its PAC.
        KdcPrincipal client = FindPrincipal(tgt.CName)
            ?? throw new KdcException(ErrorCode.ClientPrincipalUnknown);

        KdcPrincipal service = FindPrincipal(body.SName)
            ?? throw new KdcException(ErrorCode.ServicePrincipalUnknown, sname: body.SName);

        bool userToUser = options.HasFlag(KdcOption.EncTktInSkey);
        KerberosKey serviceKey = userToUser
            ? GetUserToUserTicketKey(body.AdditionalTickets, krbtgt)
            : service.PreferredKey;
        if (!userToUser)
        {
            exchange.AddKey(service, serviceKey);
        }

        // A user to user ticket is encrypted with a session key so the service's long-term keys do not apply.
        EncryptionType? sessionEType = userToUser
            ? requestedETypes.FirstOrDefault(PrincipalStore.SupportedEncryptionTypes.Contains)
            : TicketPolicy.SelectSessionKeyType(requestedETypes, service);
        if (sessionEType is null or 0)
        {
            throw new KdcException(ErrorCode.EncryptionTypeNotSupported,
                "The service has no key for any of the requested encryption types", body.SName);
        }

        // RFC 4120 2.6 a ticket issued from a forwarded TGT is also forwarded.
        TicketFlag flags = tgtFlags & (TicketFlag.PreAuthenticated | TicketFlag.Forwarded);
        KrbHostAddress[]? addresses = tgt.CAddr;
        if (options.HasFlag(KdcOption.Forwarded))
        {
            if (!tgtFlags.HasFlag(TicketFlag.Forwardable))
            {
                throw new KdcException(ErrorCode.BadOption, "The ticket is not forwardable",
                    body.SName);
            }

            // A NotDelegated client never gets a forwardable TGT, but one issued before the principal had the flag
            // still is.
            if (client.State.Flags.HasFlag(PacUserAccountControl.NotDelegated))
            {
                throw new KdcException(ErrorCode.BadOption,
                    "The client principal cannot be delegated", body.SName);
            }

            // RFC 4120 2.6 a forwarded ticket has the addresses of the request, usually none so it can be used
            // from another host.
            flags |= TicketFlag.Forwarded;
            addresses = body.Addresses;
        }

        TicketTimes times;
        if (options.HasFlag(KdcOption.Renew))
        {
            // RFC 4120 3.3.3.1. a renewed ticket keeps its renew-till and lifetime, the TGT was already checked to
            // not have expired. Only TGTs are accepted above so a renewal must name the krbtgt.
            if (service.Principal != krbtgt.Principal)
            {
                throw new KdcException(ErrorCode.ServerNoMatch,
                    "The service of a renewal request must be the service of the ticket being renewed", body.SName);
            }
            if (!tgtFlags.HasFlag(TicketFlag.Renewable) || tgt.RenewTill is null)
            {
                throw new KdcException(ErrorCode.BadOption, "The ticket is not renewable",
                    body.SName);
            }
            if (tgt.RenewTill <= now)
            {
                throw new KdcException(ErrorCode.TicketExpired,
                    "The renewable lifetime of the ticket has passed", body.SName);
            }

            flags |= tgtFlags & (TicketFlag.Forwardable | TicketFlag.Renewable);
            if (client.State.Flags.HasFlag(PacUserAccountControl.NotDelegated))
            {
                flags &= ~TicketFlag.Forwardable;
            }
            TimeSpan lifetime = tgt.EndTime - (tgt.StartTime ?? tgt.AuthTime);
            DateTimeOffset end = now + lifetime;
            times = new TicketTimes(now, end < tgt.RenewTill.Value ? end : tgt.RenewTill.Value, tgt.RenewTill);
        }
        else
        {
            if (options.HasFlag(KdcOption.Forwardable)
                && tgtFlags.HasFlag(TicketFlag.Forwardable)
                && !client.State.Flags.HasFlag(PacUserAccountControl.NotDelegated))
            {
                flags |= TicketFlag.Forwardable;
            }

            // The new ticket cannot outlive the TGT and is only renewable if the TGT is.
            times = TicketPolicy.Compute(
                body,
                now,
                ref flags,
                maxEndTime: tgt.EndTime,
                maxRenewTill: tgtFlags.HasFlag(TicketFlag.Renewable) ? tgt.RenewTill : now);
        }

        // MS-SAMR USER_TRUSTED_FOR_DELEGATION clients can delegate to the service, Windows only delegates to a
        // service with OK-AS-DELEGATE.
        if (service.State.Flags.HasFlag(PacUserAccountControl.TrustedForDelegation))
        {
            flags |= TicketFlag.OkAsDelegate;
        }

        // RFC 4120 3.3.3. the reply is encrypted with the authenticator subkey if there is one.
        (KerberosKey replyKey, KeyUsage replyKeyUsage) = authenticator.Subkey is KrbEncryptionKey subkey
            ? (subkey.AsKey(), KeyUsage.TgsRepEncryptedPartSubkey)
            : (tgt.Key.AsKey(), KeyUsage.TgsRepEncryptedPartSessionKey);

        return IssueTicket(new TicketRequest
        {
            IsAsReq = false,
            Client = client,
            ClientName = tgt.CName,
            // RFC 6806 6. the sname of a TGS reply must match the request, a ticket for an alias keeps the alias.
            ServiceName = body.SName!,
            ServiceKey = serviceKey,
            SessionEType = sessionEType.Value,
            Flags = flags,
            Times = times,
            // RFC 4120 5.3. the auth time is the time of the initial authentication.
            AuthTime = tgt.AuthTime,
            Now = now,
            Addresses = addresses,
            Nonce = body.Nonce,
            SupportedEncryptionTypes = service.EncodeSupportedEncryptionTypes(),
            IncludePac = (GetPacRequest(tgsReq)
                ?? tgt.AuthorizationData?.Any(a => a.Type.ToObol() == AuthorizationDataType.IfRelevant)
                ?? false) && TakesPac(service),
            ReplyKey = replyKey,
            ReplyKeyUsage = replyKeyUsage,
            PaData = null,
        }, exchange);
    }

    /// <summary>Records the service asked for before the request is checked, so a rejected one shows it.</summary>
    private static void RecordRequest(KdcExchange exchange, KrbKdcReqBody body)
        => exchange.ServiceName = FormatName(body.SName, body.Realm);

    /// <summary>The encryption types of a request as Obol types, one Obol has no name for keeps its number.</summary>
    private static EncryptionType[] ToObol(KrbEncryptionType[]? etypes)
        => [.. (etypes ?? []).Select(e => e.ToObol())];

    /// <summary>Finds the first pre-authentication element of a type.</summary>
    private static KrbPaData? FindPaData(KrbKdcReq request, PreAuthDataType type)
        => request.PaData?.FirstOrDefault(p => p.Type.ToObol() == type);

    /// <summary>Formats a principal name as <c>name@realm</c>, null if the request has no name.</summary>
    private static string? FormatName(KrbPrincipalName? name, string? realm)
    {
        if (name?.Name is not string[] components)
        {
            return null;
        }

        string unparsed = PrincipalName.Unparse(components);
        return realm is null ? unparsed : $"{unparsed}@{realm}";
    }

    /// <summary>Whether a ticket for the service can have a PAC.</summary>
    /// <remarks>
    /// MS-KILE 3.3.5.3 a service ticket has no PAC when the service has USER_NO_AUTH_DATA_REQUIRED, MIT's
    /// no_auth_data_required. A TGT always has one, the krbtgt flag is ignored.
    /// </remarks>
    private static bool TakesPac(KdcPrincipal service)
        => service.Principal.IsKrbtgt || !service.State.Flags.HasFlag(PacUserAccountControl.NoAuthDataRequired);

    /// <summary>Checks the protocol version and realm of a request.</summary>
    private void CheckRequest(int pvno, string? realm)
    {
        if (pvno != 5)
        {
            throw new KdcException(ErrorCode.BadVersion,
                $"The protocol version {pvno} is not supported");
        }

        // Realms are case sensitive, RFC 4120 6.1.
        if (!string.Equals(realm, Realm, StringComparison.Ordinal))
        {
            throw new KdcException(ErrorCode.WrongRealm,
                $"The KDC does not serve the realm '{realm}'");
        }
    }

    /// <summary>Finds a principal of the realm by name.</summary>
    /// <remarks>
    /// The name type is ignored like the MIT KDC, only the name components are compared. The realm is not checked as
    /// the realm of the request was checked.
    /// </remarks>
    private KdcPrincipal? FindPrincipal(KrbPrincipalName? principalName)
    {
        string[]? components = principalName?.Name;
        if (components is null)
        {
            return null;
        }

        ObolPrincipal? principal = _store.Find(components);
        if (principal is null && components.Length == 1)
        {
            // An enterprise name, RFC 6806 5., is a single component like user@example.test which Windows sends. The
            // Kerberos.NET client also sends the user this way for NT-PRINCIPAL. A principal whose name is that
            // component, with an escaped '@', was checked first. The suffix is a DNS domain so it is matched case
            // insensitively, only the KDC realm is supported as there are no UPN suffixes.
            string name = components[0];
            int suffixIndex = name.LastIndexOf('@');
            if (suffixIndex != -1
                && string.Equals(name[(suffixIndex + 1)..], Realm, StringComparison.OrdinalIgnoreCase)
                && PrincipalName.TryParse(
                    name[..suffixIndex],
                    out string[]? nameComponents,
                    out string? nameRealm,
                    out _)
                && nameRealm is null)
            {
                principal = _store.Find(nameComponents);
            }
        }

        return principal is null ? null : new KdcPrincipal(principal);
    }

    /// <summary>Validates PA-ENC-TIMESTAMP with the client's key for the encryption type the client used.</summary>
    /// <returns>The key the client used, the reply is encrypted with it.</returns>
    private static KerberosKey ValidateTimestamp(
        KrbPaData timestampData,
        KdcPrincipal client,
        DateTimeOffset now,
        KdcExchange exchange)
    {
        EncryptionType etype = KrbEncryptedData.Decode(timestampData.Value).EType.ToObol();
        KerberosKey key = client.GetKey(etype)
            ?? throw new KdcException(ErrorCode.PreAuthFailed,
                $"The principal has no key for the encryption type {etype}");

        DateTimeOffset timestamp;
        try
        {
            KrbPaEncTsEnc decrypted = KrbEncryptedData.Decode(timestampData.Value)
                .Decrypt(key, KeyUsage.PaEncTimestamp.ToKerberosNet(), b => KrbPaEncTsEnc.Decode(b));
            exchange.Timestamp = decrypted;
            timestamp = decrypted.PaTimestamp.AddTicks((decrypted.PaUSec ?? 0) * 10L);
        }
        catch (Exception e) when (e is SecurityException or CryptographicException)
        {
            // A wrong password fails the integrity check.
            throw new KdcException(ErrorCode.PreAuthFailed,
                "Failed to decrypt the pre-authentication timestamp");
        }

        if ((now - timestamp).Duration() > TicketPolicy.MaximumSkew)
        {
            throw new KdcException(ErrorCode.Skew,
                $"The pre-authentication timestamp {timestamp:O} is outside the allowed skew " +
                $"{TicketPolicy.MaximumSkew} of {now:O}");
        }

        return key;
    }

    /// <summary>
    /// Creates PA-ETYPE-INFO2 with the salts of the client's keys for the requested encryption types.
    /// </summary>
    /// <remarks>RFC 4120 5.2.7.5 lists the types in the client's order of preference.</remarks>
    private static KrbPaData CreateETypeInfo2(KdcPrincipal client, EncryptionType[] etypes)
    {
        KrbETypeInfo2Entry[] entries = [.. etypes
            .Distinct()
            .Select(client.GetKey)
            .OfType<KerberosKey>()
            .Select(k => new KrbETypeInfo2Entry
            {
                EType = k.EncryptionType,
                Salt = k.Salt,
            })];

        return new KrbPaData
        {
            Type = PreAuthDataType.ETypeInfo2.ToKerberosNet(),
            Value = new KrbETypeInfo2 { ETypeInfo = entries }.Encode(),
        };
    }

    /// <summary>Gets whether the client asked for a PAC with PA-PAC-REQUEST.</summary>
    private static bool? GetPacRequest(KrbKdcReq request)
    {
        KrbPaData? pacRequest = FindPaData(request, PreAuthDataType.PacRequest);
        return pacRequest is null ? null : KrbPaPacRequest.Decode(pacRequest.Value).IncludePac;
    }

    /// <summary>Decrypts and validates the TGT and authenticator of a TGS-REQ, RFC 4120 3.3.2.</summary>
    private (KrbEncTicketPart Tgt, KrbAuthenticator Authenticator) ValidateTgsAuthentication(
        KrbTgsReq tgsReq,
        ReadOnlyMemory<byte> message,
        KdcPrincipal krbtgt,
        DateTimeOffset now,
        KdcExchange exchange)
    {
        KrbPaData tgsPaData = FindPaData(tgsReq, PreAuthDataType.TgsReq)
            ?? throw new KdcException(ErrorCode.PaDataTypeNotSupported,
                "The request has no PA-TGS-REQ");
        KrbApReq apReq = tgsPaData.DecodeApReq();
        exchange.ApReq = apReq;
        exchange.ApReqBytes = tgsPaData.Value;
        KrbTicket ticket = apReq.Ticket;

        // Only TGTs issued by this KDC are accepted, there are no cross realm trusts.
        if (ticket.Realm != Realm || FindPrincipal(ticket.SName)?.Principal != krbtgt.Principal)
        {
            throw new KdcException(ErrorCode.NotUs,
                $"The ticket is not a ticket granting ticket for the realm '{Realm}'");
        }

        EncryptionType etype = ticket.EncryptedPart.EType.ToObol();
        KerberosKey key = krbtgt.GetKey(etype)
            ?? throw new KdcException(ErrorCode.BadKeyVersion,
                $"The krbtgt principal has no key for the encryption type {etype}");
        if (ticket.EncryptedPart.KeyVersionNumber is int kvno && kvno != krbtgt.State.Kvno)
        {
            throw new KdcException(ErrorCode.BadKeyVersion,
                $"The ticket was encrypted with key version {kvno} of the krbtgt principal, the current version is " +
                $"{krbtgt.State.Kvno}");
        }
        exchange.AddKey(krbtgt, key);

        KrbEncTicketPart tgt;
        KrbAuthenticator authenticator;
        try
        {
            tgt = ticket.EncryptedPart.Decrypt(key, KeyUsage.Ticket.ToKerberosNet(),
                b => KrbEncTicketPart.DecodeApplication(b));
            exchange.Tgt = tgt;
            authenticator = apReq.Authenticator.Decrypt(
                tgt.Key.AsKey(),
                KeyUsage.PaTgsReqAuthenticator.ToKerberosNet(),
                b => KrbAuthenticator.DecodeApplication(b));
            exchange.Authenticator = authenticator;
        }
        catch (Exception e) when (e is SecurityException or CryptographicException)
        {
            throw new KdcException(ErrorCode.BadIntegrity,
                "Failed to decrypt the ticket or authenticator");
        }

        if (authenticator.CRealm != tgt.CRealm
            || !(authenticator.CName?.Name ?? []).SequenceEqual(tgt.CName?.Name ?? []))
        {
            throw new KdcException(ErrorCode.BadMatch,
                "The client of the authenticator does not match the ticket");
        }

        TimeSpan skew = TicketPolicy.MaximumSkew;
        DateTimeOffset ctime = authenticator.CTime.AddTicks(authenticator.CuSec * 10);
        if ((now - ctime).Duration() > skew)
        {
            throw new KdcException(ErrorCode.Skew,
                $"The authenticator time {ctime:O} is outside the allowed skew {skew} of {now:O}");
        }
        if ((tgt.StartTime ?? tgt.AuthTime) > now + skew)
        {
            throw new KdcException(ErrorCode.TicketNotYetValid, "The ticket is not yet valid");
        }
        if (tgt.EndTime < now - skew)
        {
            throw new KdcException(ErrorCode.TicketExpired, "The ticket has expired");
        }

        ValidateBodyChecksum(authenticator.Checksum, message, tgt.Key.AsKey());

        return (tgt, authenticator);
    }

    /// <summary>Validates the checksum of the TGS-REQ body in the authenticator, RFC 4120 3.3.2.</summary>
    /// <remarks>
    /// The checksum stops the body from being changed, such as the service, as the TGT and authenticator can be
    /// replayed within the clock skew. It is computed over the body as the client encoded it.
    /// </remarks>
    private static void ValidateBodyChecksum(KrbChecksum? checksum, ReadOnlyMemory<byte> message, KerberosKey key)
    {
        if (checksum is null)
        {
            throw new KdcException(ErrorCode.InappropriateChecksum,
                "The authenticator has no checksum of the request body");
        }

        // RFC 4120 3.3.2 and 5.2.7.1 only require the checksum to be collision-proof, it does not need a key as the
        // authenticator is encrypted with the TGT session key. Windows sends an RSA-MD5 checksum whatever the
        // session key type, MIT and Heimdal accept it too. Finding another body with the same MD5 needs a second
        // preimage, not a collision, as the client built the body. The other unkeyed types get
        // KRB_AP_ERR_INAPP_CKSUM, unlike MIT which accepts RSA-MD4 and SHA-1, and any other type not supported gets
        // KDC_ERR_SUMTYPE_NOSUPP.
        ChecksumType type = checksum.Type.ToObol();
        if (type == ChecksumType.RsaMd5)
        {
            byte[] hash = MD5.HashData(GetTgsReqBody(message).Span);
            if (!CryptographicOperations.FixedTimeEquals(hash, checksum.Checksum.Span))
            {
                throw new KdcException(ErrorCode.Modified,
                    "The checksum of the request body is not valid");
            }
            return;
        }
        if (s_unkeyedChecksumTypes.Contains(type))
        {
            throw new KdcException(ErrorCode.InappropriateChecksum,
                $"The unkeyed checksum type {(int)type} of the request body is not accepted");
        }
        if (type is not (ChecksumType.HmacSha1Aes128
            or ChecksumType.HmacSha1Aes256
            or ChecksumType.HmacSha256Aes128
            or ChecksumType.HmacSha384Aes256))
        {
            throw new KdcException(ErrorCode.ChecksumTypeNotSupported,
                $"The checksum type {(int)type} of the request body is not supported");
        }

        // RFC 3961 each AES encryption type has one keyed checksum type, like MIT another type is rejected.
        // A session key of another type is not from a TGT this KDC issued.
        EncryptionType keyType = key.EncryptionType.ToObol();
        ChecksumType? expectedType = keyType switch
        {
            EncryptionType.Aes128Sha1 => ChecksumType.HmacSha1Aes128,
            EncryptionType.Aes256Sha1 => ChecksumType.HmacSha1Aes256,
            EncryptionType.Aes128Sha256 => ChecksumType.HmacSha256Aes128,
            EncryptionType.Aes256Sha384 => ChecksumType.HmacSha384Aes256,
            _ => null,
        };
        if (type != expectedType)
        {
            throw new KdcException(ErrorCode.InappropriateChecksum,
                $"The checksum type {type} of the request body is not the checksum type of the session key type " +
                $"{keyType}");
        }

        KrbChecksum expected = KrbChecksum.Create(GetTgsReqBody(message), key,
            KeyUsage.PaTgsReqChecksum.ToKerberosNet(), type.ToKerberosNet());
        if (!CryptographicOperations.FixedTimeEquals(expected.Checksum.Span, checksum.Checksum.Span))
        {
            throw new KdcException(ErrorCode.Modified,
                "The checksum of the request body is not valid");
        }
    }

    /// <summary>Gets the encoded req-body of a TGS-REQ.</summary>
    private static ReadOnlyMemory<byte> GetTgsReqBody(ReadOnlyMemory<byte> message)
    {
        // TGS-REQ ::= [APPLICATION 12] KDC-REQ, KDC-REQ ::= SEQUENCE { ..., req-body [4] KDC-REQ-BODY }
        AsnReader reader = new AsnReader(message, AsnEncodingRules.DER)
            .ReadSequence(new Asn1Tag(TagClass.Application, TgsReqTag))
            .ReadSequence();
        // The request was already decoded so the req-body is there.
        Asn1Tag bodyTag = new(TagClass.ContextSpecific, 4);
        while (!reader.PeekTag().HasSameClassAndValue(bodyTag))
        {
            reader.ReadEncodedValue();
        }

        return reader.ReadSequence(bodyTag).ReadEncodedValue();
    }

    /// <summary>Gets the session key of the TGT in the additional tickets, it encrypts a user to user ticket.</summary>
    private static KerberosKey GetUserToUserTicketKey(KrbTicket[]? tickets, KdcPrincipal krbtgt)
    {
        if (tickets is null || tickets.Length == 0)
        {
            throw new KdcException(ErrorCode.BadOption,
                "User to user authentication was requested without an additional ticket");
        }

        KrbEncryptedData encrypted = tickets[0].EncryptedPart;
        KerberosKey key = krbtgt.GetKey(encrypted.EType.ToObol())
            ?? throw new KdcException(ErrorCode.BadOption,
                "The additional ticket is not a ticket granting ticket");
        try
        {
            return encrypted.Decrypt(key, KeyUsage.Ticket.ToKerberosNet(), b => KrbEncTicketPart.DecodeApplication(b))
                .Key.AsKey();
        }
        catch (Exception e) when (e is SecurityException or CryptographicException)
        {
            throw new KdcException(ErrorCode.BadOption,
                "The additional ticket is not a ticket granting ticket");
        }
    }

    /// <summary>Issues a ticket and builds the AS-REP or TGS-REP for it.</summary>
    private ReadOnlyMemory<byte> IssueTicket(TicketRequest request, KdcExchange exchange)
    {
        KrbEncryptionKey sessionKey = KrbEncryptionKey.Generate(request.SessionEType.ToKerberosNet());
        KrbHostAddress[] addresses = request.Addresses ?? [];

        KrbEncTicketPart encTicketPart = new()
        {
            Flags = request.Flags.ToKerberosNet(),
            Key = sessionKey,
            CRealm = Realm,
            CName = request.ClientName,
            Transited = new KrbTransitedEncoding(),
            AuthTime = request.AuthTime,
            StartTime = request.Times.Start,
            EndTime = request.Times.End,
            RenewTill = request.Times.RenewTill,
            CAddr = addresses,
            AuthorizationData = request.IncludePac ? [CreatePacAuthorizationData(request)] : [],
        };

        KrbTicket ticket = new()
        {
            Realm = Realm,
            SName = request.ServiceName,
            EncryptedPart = KrbEncryptedData.Encrypt(
                encTicketPart.EncodeApplication(),
                request.ServiceKey,
                KeyUsage.Ticket.ToKerberosNet()),
        };

        KrbEncKdcRepPart encPart = request.IsAsReq ? new KrbEncAsRepPart() : new KrbEncTgsRepPart();
        encPart.Key = sessionKey;
        encPart.LastReq = [new KrbLastReq { Type = 0, Value = request.Now }];
        encPart.Nonce = request.Nonce;
        encPart.Flags = request.Flags.ToKerberosNet();
        encPart.AuthTime = request.AuthTime;
        encPart.StartTime = request.Times.Start;
        encPart.EndTime = request.Times.End;
        encPart.RenewTill = request.Times.RenewTill;
        encPart.Realm = Realm;
        encPart.SName = request.ServiceName;
        encPart.CAddr = addresses;
        // The MS-KILE PA-SUPPORTED-ENCTYPES tells the client the encryption types the service supports.
        encPart.EncryptedPaData = new KrbMethodData
        {
            MethodData =
            [
                new KrbPaData
                {
                    Type = PreAuthDataType.SupportedEncryptionTypes.ToKerberosNet(),
                    Value = request.SupportedEncryptionTypes,
                },
            ],
        };

        KrbKdcRep rep = request.IsAsReq ? new KrbAsRep() : new KrbTgsRep();
        rep.MessageType = (request.IsAsReq ? MessageType.AsRep : MessageType.TgsRep).ToKerberosNet();
        rep.PaData = request.PaData;
        rep.CRealm = Realm;
        rep.CName = request.ClientName;
        rep.Ticket = ticket;
        rep.EncryptedPart = KrbEncryptedData.Encrypt(
            encPart.EncodeApplication(),
            request.ReplyKey,
            request.ReplyKeyUsage.ToKerberosNet());

        exchange.Reply = rep;
        exchange.IssuedTicketPart = encTicketPart;
        exchange.ReplyPart = encPart;
        return rep is KrbAsRep asRep ? asRep.EncodeApplication() : ((KrbTgsRep)rep).EncodeApplication();
    }

    /// <summary>Creates the AD-IF-RELEVANT element with the PAC of the client.</summary>
    private KrbAuthorizationData CreatePacAuthorizationData(TicketRequest request)
    {
        PrivilegedAttributeCertificate pac = request.Client.GeneratePac(request.AuthTime);

        // MS-PAC 2.7 the client info has the auth time and client name of the ticket, MIT checks both. MIT parses
        // the name back, an enterprise name is a single component with an unescaped '@'.
        KrbPrincipalName clientName = request.ClientName;
        pac.ClientInformation = new KrbPacClientInfo
        {
            ClientId = RpcFileTime.ConvertWithoutMicroseconds(request.AuthTime),
            Name = clientName.Type.ToObol() == PrincipalNameType.Enterprise && clientName.Name.Length == 1
                ? clientName.Name[0]
                : PrincipalName.Unparse(clientName.Name),
        };

        KrbAuthorizationDataSequence sequence = new()
        {
            AuthorizationData =
            [
                new KrbAuthorizationData
                {
                    Type = AuthorizationDataType.Win2kPac.ToKerberosNet(),
                    Data = pac.Encode(new KdcPrincipal(_store.Krbtgt).PreferredKey, request.ServiceKey),
                },
            ],
        };

        return new KrbAuthorizationData
        {
            Type = AuthorizationDataType.IfRelevant.ToKerberosNet(),
            Data = sequence.Encode(),
        };
    }

    /// <summary>The values of a ticket to issue.</summary>
    private sealed class TicketRequest
    {
        public required bool IsAsReq { get; init; }

        /// <summary>The client the ticket is issued to, the PAC is for it.</summary>
        public required KdcPrincipal Client { get; init; }

        public required KrbPrincipalName ClientName { get; init; }

        public required KrbPrincipalName ServiceName { get; init; }

        /// <summary>The key the ticket is encrypted with.</summary>
        public required KerberosKey ServiceKey { get; init; }

        public required EncryptionType SessionEType { get; init; }

        public required TicketFlag Flags { get; init; }

        public required TicketTimes Times { get; init; }

        public required DateTimeOffset AuthTime { get; init; }

        public required DateTimeOffset Now { get; init; }

        public required KrbHostAddress[]? Addresses { get; init; }

        public required int Nonce { get; init; }

        /// <summary>The PA-SUPPORTED-ENCTYPES value of the service.</summary>
        public required ReadOnlyMemory<byte> SupportedEncryptionTypes { get; init; }

        public required bool IncludePac { get; init; }

        /// <summary>The key the encrypted part of the reply is encrypted with.</summary>
        public required KerberosKey ReplyKey { get; init; }

        public required KeyUsage ReplyKeyUsage { get; init; }

        /// <summary>The padata of the reply.</summary>
        public required KrbPaData[]? PaData { get; init; }
    }
}
