using System;
using System.Formats.Asn1;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;

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
    private const int AsReqTag = 10;
    private const int TgsReqTag = 12;

    /// <summary>The RFC 3961 RSA-MD5 checksum type, Windows uses it for the TGS-REQ body checksum.</summary>
    private const int RsaMd5ChecksumType = 7;

    /// <summary>The other RFC 3961 checksum types that are not keyed: CRC32, RSA-MD4 and SHA-1.</summary>
    private static readonly int[] s_unkeyedChecksumTypes = [1, 2, 14];

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
    public ReadOnlyMemory<byte> Process(ReadOnlyMemory<byte> request)
    {
        try
        {
            Asn1Tag tag = new AsnReader(request, AsnEncodingRules.DER).PeekTag();
            if (tag.TagClass == TagClass.Application && tag.TagValue == AsReqTag)
            {
                return ProcessAsReq(request);
            }
            if (tag.TagClass == TagClass.Application && tag.TagValue == TgsReqTag)
            {
                return ProcessTgsReq(request);
            }

            throw new KdcException(KerberosErrorCode.KRB_ERR_GENERIC,
                $"Failed to process request: the message type {tag} is not supported");
        }
        catch (KdcException e)
        {
            return CreateError(e.Code, e.Text, e.SName, e.ErrorData);
        }
        catch (Exception e)
        {
            // Such as a request that is not valid DER or misses a required field.
            return CreateError(KerberosErrorCode.KRB_ERR_GENERIC, $"Failed to process request: {e.Message}");
        }
    }

    /// <summary>Creates the KRB_ERR_FIELD_TOOLONG error for a TCP request that is too long to read.</summary>
    public ReadOnlyMemory<byte> CreateRequestTooLongError(string text)
        => CreateError(KerberosErrorCode.KRB_ERR_FIELD_TOOLONG, text);

    /// <summary>Creates the KRB_ERR_RESPONSE_TOO_BIG error that replaces a reply too big for UDP.</summary>
    public ReadOnlyMemory<byte> CreateResponseTooBigError(string text)
        => CreateError(KerberosErrorCode.KRB_ERR_RESPONSE_TOO_BIG, text);

    /// <summary>Creates a KRB-ERROR from the KDC.</summary>
    /// <param name="code">The error code.</param>
    /// <param name="text">The e-text, if any.</param>
    /// <param name="sname">The sname, the krbtgt of the realm if not set.</param>
    /// <param name="errorData">The e-data, if any.</param>
    private ReadOnlyMemory<byte> CreateError(
        KerberosErrorCode code,
        string? text,
        KrbPrincipalName? sname = null,
        ReadOnlyMemory<byte>? errorData = null)
    {
        KrbError error = new()
        {
            ErrorCode = code,
            EText = text,
            Realm = Realm,
            SName = sname ?? _krbtgtName,
            EData = errorData,
        };
        error.StampServerTime();

        return error.EncodeApplication();
    }

    private ReadOnlyMemory<byte> ProcessAsReq(ReadOnlyMemory<byte> message)
    {
        KrbAsReq asReq = KrbAsReq.DecodeApplication(message);
        KrbKdcReqBody body = asReq.Body;
        CheckRequest(asReq.ProtocolVersionNumber, body.Realm);

        KdcPrincipal client = FindPrincipal(body.CName)
            ?? throw new KdcException(KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);

        // An AS-REQ is usually for the krbtgt but can be for any service, like kadmin/changepw.
        KdcPrincipal service = FindPrincipal(body.SName)
            ?? throw new KdcException(KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN, sname: body.SName);

        DateTimeOffset now = _time.GetUtcNow();
        bool preauthenticated = false;
        KerberosKey replyKey;
        KrbPaData? timestamp = asReq.PaData?.FirstOrDefault(p => p.Type == PaDataType.PA_ENC_TIMESTAMP);
        if (timestamp is not null)
        {
            // A timestamp is checked even if the principal does not require pre-auth, like the MIT KDC.
            replyKey = ValidateTimestamp(asReq, timestamp, client, now);
            preauthenticated = true;
        }
        else
        {
            // Without pre-auth the reply is encrypted with the client's preferred key it has.
            replyKey = body.EType
                .Select(client.GetKey)
                .FirstOrDefault(k => k is not null)
                ?? throw new KdcException(KerberosErrorCode.KDC_ERR_ETYPE_NOSUPP,
                    "The client has no key for any of the requested encryption types");

            if (!client.State.Flags.HasFlag(ObolPrincipalFlag.DoesNotRequirePreAuth))
            {
                KrbMethodData methodData = new()
                {
                    MethodData =
                    [
                        new KrbPaData { Type = PaDataType.PA_ENC_TIMESTAMP },
                        CreateETypeInfo2(client, body.EType),
                    ],
                };
                throw new KdcException(KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED, errorData: methodData.Encode());
            }
        }

        EncryptionType sessionEType = TicketPolicy.SelectSessionKeyType(body.EType, service)
            ?? throw new KdcException(KerberosErrorCode.KDC_ERR_ETYPE_NOSUPP,
                "The service has no key for any of the requested encryption types");

        // Only the options the client asked for are granted, RFC 4120 3.1.3.
        TicketFlags flags = TicketFlags.Initial;
        if (preauthenticated)
        {
            flags |= TicketFlags.PreAuthenticated;
        }
        // MS-SAMR USER_NOT_DELEGATED the ticket is not forwardable even if requested.
        if (body.KdcOptions.HasFlag(KdcOptions.Forwardable)
            && !client.State.Flags.HasFlag(ObolPrincipalFlag.NotDelegated))
        {
            flags |= TicketFlags.Forwardable;
        }
        if (service.State.Flags.HasFlag(ObolPrincipalFlag.TrustedForDelegation))
        {
            flags |= TicketFlags.OkAsDelegate;
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
            ReplyKeyUsage = KeyUsage.EncAsRepPart,
            // The salt used for the reply key, the client uses it instead of the default salt of the name it sent
            // which differs for an alias.
            PaData = [CreateETypeInfo2(client, [replyKey.EncryptionType])],
        });
    }

    private ReadOnlyMemory<byte> ProcessTgsReq(ReadOnlyMemory<byte> message)
    {
        KrbTgsReq tgsReq = KrbTgsReq.DecodeApplication(message);
        KrbKdcReqBody body = tgsReq.Body;
        CheckRequest(tgsReq.ProtocolVersionNumber, body.Realm);

        DateTimeOffset now = _time.GetUtcNow();
        KdcPrincipal krbtgt = new(_store.Krbtgt);
        (KrbEncTicketPart tgt, KrbAuthenticator authenticator) = ValidateTgsAuthentication(
            tgsReq, message, krbtgt, now);

        // RFC 4120 3.3.3. the client name is copied from the TGT, the client must still exist for its PAC.
        KdcPrincipal client = FindPrincipal(tgt.CName)
            ?? throw new KdcException(KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);

        KdcPrincipal service = FindPrincipal(body.SName)
            ?? throw new KdcException(KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN, sname: body.SName);

        bool userToUser = body.KdcOptions.HasFlag(KdcOptions.EncTktInSkey);
        KerberosKey serviceKey = userToUser
            ? GetUserToUserTicketKey(body.AdditionalTickets, krbtgt)
            : service.PreferredKey;

        // A user to user ticket is encrypted with a session key so the service's long-term keys do not apply.
        EncryptionType? sessionEType = userToUser
            ? body.EType.FirstOrDefault(PrincipalStore.SupportedEncryptionTypes.Contains)
            : TicketPolicy.SelectSessionKeyType(body.EType, service);
        if (sessionEType is null or 0)
        {
            throw new KdcException(KerberosErrorCode.KDC_ERR_ETYPE_NOSUPP,
                "The service has no key for any of the requested encryption types", body.SName);
        }

        // RFC 4120 2.6 a ticket issued from a forwarded TGT is also forwarded.
        TicketFlags flags = tgt.Flags & (TicketFlags.PreAuthenticated | TicketFlags.Forwarded);
        KrbHostAddress[]? addresses = tgt.CAddr;
        if (body.KdcOptions.HasFlag(KdcOptions.Forwarded))
        {
            if (!tgt.Flags.HasFlag(TicketFlags.Forwardable))
            {
                throw new KdcException(KerberosErrorCode.KDC_ERR_BADOPTION, "The ticket is not forwardable",
                    body.SName);
            }

            // A NotDelegated client never gets a forwardable TGT, but one issued before the principal had the flag
            // still is.
            if (client.State.Flags.HasFlag(ObolPrincipalFlag.NotDelegated))
            {
                throw new KdcException(KerberosErrorCode.KDC_ERR_BADOPTION,
                    "The client principal cannot be delegated", body.SName);
            }

            // RFC 4120 2.6 a forwarded ticket has the addresses of the request, usually none so it can be used
            // from another host.
            flags |= TicketFlags.Forwarded;
            addresses = body.Addresses;
        }

        TicketTimes times;
        if (body.KdcOptions.HasFlag(KdcOptions.Renew))
        {
            // RFC 4120 3.3.3.1. a renewed ticket keeps its renew-till and lifetime, the TGT was already checked to
            // not have expired. Only TGTs are accepted above so a renewal must name the krbtgt.
            if (service.Principal != krbtgt.Principal)
            {
                throw new KdcException(KerberosErrorCode.KDC_ERR_SERVER_NOMATCH,
                    "The service of a renewal request must be the service of the ticket being renewed", body.SName);
            }
            if (!tgt.Flags.HasFlag(TicketFlags.Renewable) || tgt.RenewTill is null)
            {
                throw new KdcException(KerberosErrorCode.KDC_ERR_BADOPTION, "The ticket is not renewable",
                    body.SName);
            }
            if (tgt.RenewTill <= now)
            {
                throw new KdcException(KerberosErrorCode.KRB_AP_ERR_TKT_EXPIRED,
                    "The renewable lifetime of the ticket has passed", body.SName);
            }

            flags |= tgt.Flags & (TicketFlags.Forwardable | TicketFlags.Renewable);
            if (client.State.Flags.HasFlag(ObolPrincipalFlag.NotDelegated))
            {
                flags &= ~TicketFlags.Forwardable;
            }
            TimeSpan lifetime = tgt.EndTime - (tgt.StartTime ?? tgt.AuthTime);
            DateTimeOffset end = now + lifetime;
            times = new TicketTimes(now, end < tgt.RenewTill.Value ? end : tgt.RenewTill.Value, tgt.RenewTill);
        }
        else
        {
            if (body.KdcOptions.HasFlag(KdcOptions.Forwardable)
                && tgt.Flags.HasFlag(TicketFlags.Forwardable)
                && !client.State.Flags.HasFlag(ObolPrincipalFlag.NotDelegated))
            {
                flags |= TicketFlags.Forwardable;
            }

            // The new ticket cannot outlive the TGT and is only renewable if the TGT is.
            times = TicketPolicy.Compute(
                body,
                now,
                ref flags,
                maxEndTime: tgt.EndTime,
                maxRenewTill: tgt.Flags.HasFlag(TicketFlags.Renewable) ? tgt.RenewTill : now);
        }

        // MS-SAMR USER_TRUSTED_FOR_DELEGATION clients can delegate to the service, Windows only delegates to a
        // service with OK-AS-DELEGATE.
        if (service.State.Flags.HasFlag(ObolPrincipalFlag.TrustedForDelegation))
        {
            flags |= TicketFlags.OkAsDelegate;
        }

        // RFC 4120 3.3.3. the reply is encrypted with the authenticator subkey if there is one.
        (KerberosKey replyKey, KeyUsage replyKeyUsage) = authenticator.Subkey is KrbEncryptionKey subkey
            ? (subkey.AsKey(), KeyUsage.EncTgsRepPartSubSessionKey)
            : (tgt.Key.AsKey(), KeyUsage.EncTgsRepPartSessionKey);

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
                ?? tgt.AuthorizationData?.Any(a => a.Type == AuthorizationDataType.AdIfRelevant)
                ?? false) && TakesPac(service),
            ReplyKey = replyKey,
            ReplyKeyUsage = replyKeyUsage,
            PaData = null,
        });
    }

    /// <summary>Whether a ticket for the service can have a PAC.</summary>
    /// <remarks>
    /// MS-KILE 3.3.5.3 a service ticket has no PAC when the service has USER_NO_AUTH_DATA_REQUIRED, MIT's
    /// no_auth_data_required. A TGT always has one, the krbtgt flag is ignored.
    /// </remarks>
    private static bool TakesPac(KdcPrincipal service)
        => service.Principal.IsKrbtgt || !service.State.Flags.HasFlag(ObolPrincipalFlag.NoAuthDataRequired);

    /// <summary>Checks the protocol version and realm of a request.</summary>
    private void CheckRequest(int pvno, string? realm)
    {
        if (pvno != 5)
        {
            throw new KdcException(KerberosErrorCode.KRB_AP_ERR_BADVERSION,
                $"The protocol version {pvno} is not supported");
        }

        // Realms are case sensitive, RFC 4120 6.1.
        if (!string.Equals(realm, Realm, StringComparison.Ordinal))
        {
            throw new KdcException(KerberosErrorCode.KDC_ERR_WRONG_REALM,
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
        KrbAsReq asReq,
        KrbPaData timestampData,
        KdcPrincipal client,
        DateTimeOffset now)
    {
        EncryptionType etype = KrbEncryptedData.Decode(timestampData.Value).EType;
        KerberosKey key = client.GetKey(etype)
            ?? throw new KdcException(KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                $"The principal has no key for the encryption type {etype}");

        DateTimeOffset timestamp;
        try
        {
            timestamp = asReq.DecryptTimestamp(key);
        }
        catch (Exception e) when (e is SecurityException or CryptographicException)
        {
            // A wrong password fails the integrity check.
            throw new KdcException(KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                "Failed to decrypt the pre-authentication timestamp");
        }

        if ((now - timestamp).Duration() > TicketPolicy.MaximumSkew)
        {
            throw new KdcException(KerberosErrorCode.KRB_AP_ERR_SKEW,
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
            Type = PaDataType.PA_ETYPE_INFO2,
            Value = new KrbETypeInfo2 { ETypeInfo = entries }.Encode(),
        };
    }

    /// <summary>Gets whether the client asked for a PAC with PA-PAC-REQUEST.</summary>
    private static bool? GetPacRequest(KrbKdcReq request)
    {
        KrbPaData? pacRequest = request.PaData?.FirstOrDefault(p => p.Type == PaDataType.PA_PAC_REQUEST);
        return pacRequest is null ? null : KrbPaPacRequest.Decode(pacRequest.Value).IncludePac;
    }

    /// <summary>Decrypts and validates the TGT and authenticator of a TGS-REQ, RFC 4120 3.3.2.</summary>
    private (KrbEncTicketPart Tgt, KrbAuthenticator Authenticator) ValidateTgsAuthentication(
        KrbTgsReq tgsReq,
        ReadOnlyMemory<byte> message,
        KdcPrincipal krbtgt,
        DateTimeOffset now)
    {
        KrbPaData tgsPaData = tgsReq.PaData?.FirstOrDefault(p => p.Type == PaDataType.PA_TGS_REQ)
            ?? throw new KdcException(KerberosErrorCode.KDC_ERR_PADATA_TYPE_NOSUPP,
                "The request has no PA-TGS-REQ");
        KrbApReq apReq = tgsPaData.DecodeApReq();
        KrbTicket ticket = apReq.Ticket;

        // Only TGTs issued by this KDC are accepted, there are no cross realm trusts.
        if (ticket.Realm != Realm || FindPrincipal(ticket.SName)?.Principal != krbtgt.Principal)
        {
            throw new KdcException(KerberosErrorCode.KRB_AP_ERR_NOT_US,
                $"The ticket is not a ticket granting ticket for the realm '{Realm}'");
        }

        EncryptionType etype = ticket.EncryptedPart.EType;
        KerberosKey key = krbtgt.GetKey(etype)
            ?? throw new KdcException(KerberosErrorCode.KRB_AP_ERR_BADKEYVER,
                $"The krbtgt principal has no key for the encryption type {etype}");
        if (ticket.EncryptedPart.KeyVersionNumber is int kvno && kvno != krbtgt.State.Kvno)
        {
            throw new KdcException(KerberosErrorCode.KRB_AP_ERR_BADKEYVER,
                $"The ticket was encrypted with key version {kvno} of the krbtgt principal, the current version is " +
                $"{krbtgt.State.Kvno}");
        }

        KrbEncTicketPart tgt;
        KrbAuthenticator authenticator;
        try
        {
            tgt = ticket.EncryptedPart.Decrypt(key, KeyUsage.Ticket, b => KrbEncTicketPart.DecodeApplication(b));
            authenticator = apReq.Authenticator.Decrypt(
                tgt.Key.AsKey(),
                KeyUsage.PaTgsReqAuthenticator,
                b => KrbAuthenticator.DecodeApplication(b));
        }
        catch (Exception e) when (e is SecurityException or CryptographicException)
        {
            throw new KdcException(KerberosErrorCode.KRB_AP_ERR_BAD_INTEGRITY,
                "Failed to decrypt the ticket or authenticator");
        }

        if (authenticator.CRealm != tgt.CRealm
            || !(authenticator.CName?.Name ?? []).SequenceEqual(tgt.CName?.Name ?? []))
        {
            throw new KdcException(KerberosErrorCode.KRB_AP_ERR_BADMATCH,
                "The client of the authenticator does not match the ticket");
        }

        TimeSpan skew = TicketPolicy.MaximumSkew;
        DateTimeOffset ctime = authenticator.CTime.AddTicks(authenticator.CuSec * 10);
        if ((now - ctime).Duration() > skew)
        {
            throw new KdcException(KerberosErrorCode.KRB_AP_ERR_SKEW,
                $"The authenticator time {ctime:O} is outside the allowed skew {skew} of {now:O}");
        }
        if ((tgt.StartTime ?? tgt.AuthTime) > now + skew)
        {
            throw new KdcException(KerberosErrorCode.KRB_AP_ERR_TKT_NYV, "The ticket is not yet valid");
        }
        if (tgt.EndTime < now - skew)
        {
            throw new KdcException(KerberosErrorCode.KRB_AP_ERR_TKT_EXPIRED, "The ticket has expired");
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
            throw new KdcException(KerberosErrorCode.KRB_AP_ERR_INAPP_CKSUM,
                "The authenticator has no checksum of the request body");
        }

        // RFC 4120 3.3.2 and 5.2.7.1 only require the checksum to be collision-proof, it does not need a key as the
        // authenticator is encrypted with the TGT session key. Windows sends an RSA-MD5 checksum whatever the
        // session key type, MIT and Heimdal accept it too. Finding another body with the same MD5 needs a second
        // preimage, not a collision, as the client built the body. The other unkeyed types get
        // KRB_AP_ERR_INAPP_CKSUM, unlike MIT which accepts RSA-MD4 and SHA-1, and any other type not supported gets
        // KDC_ERR_SUMTYPE_NOSUPP.
        if ((int)checksum.Type == RsaMd5ChecksumType)
        {
            byte[] hash = MD5.HashData(GetTgsReqBody(message).Span);
            if (!CryptographicOperations.FixedTimeEquals(hash, checksum.Checksum.Span))
            {
                throw new KdcException(KerberosErrorCode.KRB_AP_ERR_MODIFIED,
                    "The checksum of the request body is not valid");
            }
            return;
        }
        if (s_unkeyedChecksumTypes.Contains((int)checksum.Type))
        {
            throw new KdcException(KerberosErrorCode.KRB_AP_ERR_INAPP_CKSUM,
                $"The unkeyed checksum type {(int)checksum.Type} of the request body is not accepted");
        }
        if (checksum.Type is not (ChecksumType.HMAC_SHA1_96_AES128
            or ChecksumType.HMAC_SHA1_96_AES256
            or ChecksumType.HMAC_SHA256_128_AES128
            or ChecksumType.HMAC_SHA384_192_AES256))
        {
            throw new KdcException(KerberosErrorCode.KDC_ERR_SUMTYPE_NOSUPP,
                $"The checksum type {(int)checksum.Type} of the request body is not supported");
        }

        // RFC 3961 each AES encryption type has one keyed checksum type, like MIT another type is rejected.
        // A session key of another type is not from a TGT this KDC issued.
        ChecksumType? expectedType = key.EncryptionType switch
        {
            EncryptionType.AES128_CTS_HMAC_SHA1_96 => ChecksumType.HMAC_SHA1_96_AES128,
            EncryptionType.AES256_CTS_HMAC_SHA1_96 => ChecksumType.HMAC_SHA1_96_AES256,
            EncryptionType.AES128_CTS_HMAC_SHA256_128 => ChecksumType.HMAC_SHA256_128_AES128,
            EncryptionType.AES256_CTS_HMAC_SHA384_192 => ChecksumType.HMAC_SHA384_192_AES256,
            _ => null,
        };
        if (checksum.Type != expectedType)
        {
            throw new KdcException(KerberosErrorCode.KRB_AP_ERR_INAPP_CKSUM,
                $"The checksum type {checksum.Type} of the request body is not the checksum type of the session key " +
                $"type {key.EncryptionType}");
        }

        KrbChecksum expected = KrbChecksum.Create(GetTgsReqBody(message), key, KeyUsage.PaTgsReqChecksum,
            checksum.Type);
        if (!CryptographicOperations.FixedTimeEquals(expected.Checksum.Span, checksum.Checksum.Span))
        {
            throw new KdcException(KerberosErrorCode.KRB_AP_ERR_MODIFIED,
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
            throw new KdcException(KerberosErrorCode.KDC_ERR_BADOPTION,
                "User to user authentication was requested without an additional ticket");
        }

        KrbEncryptedData encrypted = tickets[0].EncryptedPart;
        KerberosKey key = krbtgt.GetKey(encrypted.EType)
            ?? throw new KdcException(KerberosErrorCode.KDC_ERR_BADOPTION,
                "The additional ticket is not a ticket granting ticket");
        try
        {
            return encrypted.Decrypt(key, KeyUsage.Ticket, b => KrbEncTicketPart.DecodeApplication(b)).Key.AsKey();
        }
        catch (Exception e) when (e is SecurityException or CryptographicException)
        {
            throw new KdcException(KerberosErrorCode.KDC_ERR_BADOPTION,
                "The additional ticket is not a ticket granting ticket");
        }
    }

    /// <summary>Issues a ticket and builds the AS-REP or TGS-REP for it.</summary>
    private ReadOnlyMemory<byte> IssueTicket(TicketRequest request)
    {
        KrbEncryptionKey sessionKey = KrbEncryptionKey.Generate(request.SessionEType);
        KrbHostAddress[] addresses = request.Addresses ?? [];

        KrbEncTicketPart encTicketPart = new()
        {
            Flags = request.Flags,
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
                KeyUsage.Ticket),
        };

        KrbEncKdcRepPart encPart = request.IsAsReq ? new KrbEncAsRepPart() : new KrbEncTgsRepPart();
        encPart.Key = sessionKey;
        encPart.LastReq = [new KrbLastReq { Type = 0, Value = request.Now }];
        encPart.Nonce = request.Nonce;
        encPart.Flags = request.Flags;
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
                    Type = PaDataType.PA_SUPPORTED_ETYPES,
                    Value = request.SupportedEncryptionTypes,
                },
            ],
        };

        KrbKdcRep rep = request.IsAsReq ? new KrbAsRep() : new KrbTgsRep();
        rep.MessageType = request.IsAsReq ? MessageType.KRB_AS_REP : MessageType.KRB_TGS_REP;
        rep.PaData = request.PaData;
        rep.CRealm = Realm;
        rep.CName = request.ClientName;
        rep.Ticket = ticket;
        rep.EncryptedPart = KrbEncryptedData.Encrypt(
            encPart.EncodeApplication(),
            request.ReplyKey,
            request.ReplyKeyUsage);

        return rep is KrbAsRep asRep ? asRep.EncodeApplication() : ((KrbTgsRep)rep).EncodeApplication();
    }

    /// <summary>Creates the AD-IF-RELEVANT element with the PAC of the client.</summary>
    private KrbAuthorizationData CreatePacAuthorizationData(TicketRequest request)
    {
        PrivilegedAttributeCertificate pac = request.Client.GeneratePac(request.AuthTime);

        // MS-PAC 2.7 the client info has the auth time and client name of the ticket, MIT checks both. MIT parses
        // the name back, an enterprise name is a single component with an unescaped '@'.
        KrbPrincipalName clientName = request.ClientName;
        pac.ClientInformation = new PacClientInfo
        {
            ClientId = RpcFileTime.ConvertWithoutMicroseconds(request.AuthTime),
            Name = clientName.Type == PrincipalNameType.NT_ENTERPRISE && clientName.Name.Length == 1
                ? clientName.Name[0]
                : PrincipalName.Unparse(clientName.Name),
        };

        KrbAuthorizationDataSequence sequence = new()
        {
            AuthorizationData =
            [
                new KrbAuthorizationData
                {
                    Type = AuthorizationDataType.AdWin2kPac,
                    Data = pac.Encode(new KdcPrincipal(_store.Krbtgt).PreferredKey, request.ServiceKey),
                },
            ],
        };

        return new KrbAuthorizationData
        {
            Type = AuthorizationDataType.AdIfRelevant,
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

        public required TicketFlags Flags { get; init; }

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
