using System;
using System.Buffers.Binary;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Obol.Protocol;

namespace Obol.Tests;

/// <summary>Requests built by hand to check the validation the Kerberos.NET client cannot trigger.</summary>
public class KdcProcessorTests
{
    private const string Realm = TestKdc.Realm;
    private const string ServiceName = "HTTP/web.example.test";

    private static readonly DateTimeOffset s_start = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);

    private sealed class TestClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = s_start;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class TestRealm
    {
        public TestRealm()
        {
            Store = new PrincipalStore(Realm, caseInsensitive: false);
            Processor = new KdcProcessor(Store, Clock);
            User = Store.Create(["user"], TestKdc.ToSecureString(TestKdc.Password), flags: ObolPrincipalFlag.None);
            Service = Store.Create(ServiceName.Split('/'), password: null, flags: ObolPrincipalFlag.None);
        }

        public TestClock Clock { get; } = new();

        public PrincipalStore Store { get; }

        public KdcProcessor Processor { get; }

        public ObolPrincipal User { get; }

        public ObolPrincipal Service { get; }

        public ReadOnlyMemory<byte> Send(KrbAsReq request) => Processor.Process(request.EncodeApplication());

        public ReadOnlyMemory<byte> Send(KrbTgsReq request) => Processor.Process(request.EncodeApplication());

        /// <summary>Gets a TGT for the user with the session key from the decrypted reply.</summary>
        public (KrbAsRep Reply, KrbEncAsRepPart Part) GetTgt(Action<KrbKdcReqBody>? configureBody = null)
        {
            KerberosKey key = User.State.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96)!;
            KrbAsReq request = NewAsReq("user", key, Clock.Now);
            configureBody?.Invoke(request.Body);
            KrbAsRep reply = KrbAsRep.DecodeApplication(Send(request));
            KrbEncAsRepPart part = reply.EncryptedPart.Decrypt(
                key,
                KeyUsage.EncAsRepPart,
                b => KrbEncAsRepPart.DecodeApplication(b));
            return (reply, part);
        }
    }

    internal static KrbPrincipalName Name(params string[] components) => new()
    {
        Type = components.Length == 1 ? PrincipalNameType.NT_PRINCIPAL : PrincipalNameType.NT_SRV_INST,
        Name = components,
    };

    /// <summary>
    /// Builds an AS-REQ for the krbtgt, or another service, with a PA-ENC-TIMESTAMP if a key is given.
    /// </summary>
    internal static KrbAsReq NewAsReq(
        string user,
        KerberosKey? timestampKey,
        DateTimeOffset timestamp,
        KrbPrincipalName? sname = null,
        KrbPaData[]? paData = null)
    {
        KrbAsReq request = new()
        {
            Body = new KrbKdcReqBody
            {
                CName = Name(user),
                Realm = Realm,
                SName = sname ?? Name("krbtgt", Realm),
                Till = timestamp.AddHours(1),
                Nonce = 1234,
                EType = [EncryptionType.AES256_CTS_HMAC_SHA1_96, EncryptionType.AES128_CTS_HMAC_SHA1_96],
            },
        };

        if (timestampKey is not null)
        {
            KrbPaEncTsEnc ts = new()
            {
                PaTimestamp = timestamp,
                PaUSec = 0,
            };
            paData =
            [
                new KrbPaData
                {
                    Type = PaDataType.PA_ENC_TIMESTAMP,
                    Value = KrbEncryptedData.Encrypt(ts.Encode(), timestampKey, KeyUsage.PaEncTs).Encode(),
                },
                .. paData ?? [],
            ];
        }
        request.PaData = paData;

        return request;
    }

    private static KrbPaData PacRequest(bool includePac) => new()
    {
        Type = PaDataType.PA_PAC_REQUEST,
        Value = new KrbPaPacRequest { IncludePac = includePac }.Encode(),
    };

    /// <summary>Decrypts the reply with the client's key, the reply must be an AS-REP.</summary>
    private static KrbEncAsRepPart DecryptAsRep(KrbAsRep reply, KerberosKey key)
        => reply.EncryptedPart.Decrypt(key, KeyUsage.EncAsRepPart, b => KrbEncAsRepPart.DecodeApplication(b));

    /// <summary>Decrypts the reply with the TGT session key, the request must not have used a subkey.</summary>
    private static KrbEncTgsRepPart DecryptTgsRep(KrbTgsRep reply, KrbEncAsRepPart tgtPart)
        => reply.EncryptedPart.Decrypt(
            tgtPart.Key.AsKey(),
            KeyUsage.EncTgsRepPartSessionKey,
            b => KrbEncTgsRepPart.DecodeApplication(b));

    /// <summary>Whether the ticket has a PAC in its authorization data.</summary>
    private static bool HasPac(KrbEncTicketPart ticket)
        => ticket.AuthorizationData?.Any(a => a.Type == AuthorizationDataType.AdIfRelevant
            && KrbAuthorizationDataSequence.Decode(a.Data).AuthorizationData
                .Any(i => i.Type == AuthorizationDataType.AdWin2kPac)) ?? false;

    /// <summary>Builds a TGS-REQ for a service with the TGT, the checksum covers the body unless set.</summary>
    private static KrbTgsReq NewTgsReq(
        KrbAsRep tgt,
        KrbEncAsRepPart tgtPart,
        DateTimeOffset ctime,
        string service = ServiceName,
        KrbTicket? ticket = null,
        KrbPrincipalName? authenticatorCName = null,
        Func<KrbKdcReqBody, KrbChecksum?>? checksum = null,
        Action<KrbKdcReqBody>? configureBody = null,
        KrbPaData[]? paData = null)
    {
        KrbKdcReqBody body = new()
        {
            Realm = Realm,
            SName = Name(service.Split('/')),
            Till = ctime.AddHours(1),
            Nonce = 5678,
            EType = [EncryptionType.AES256_CTS_HMAC_SHA1_96],
        };
        configureBody?.Invoke(body);
        KerberosKey sessionKey = tgtPart.Key.AsKey();

        KrbAuthenticator authenticator = new()
        {
            CName = authenticatorCName ?? tgt.CName,
            CRealm = tgt.CRealm,
            CTime = ctime,
            CuSec = 0,
            Checksum = checksum is null
                ? KrbChecksum.Create(body.Encode(), sessionKey, KeyUsage.PaTgsReqChecksum)
                : checksum(body),
        };
        KrbApReq apReq = new()
        {
            Ticket = ticket ?? tgt.Ticket,
            Authenticator = KrbEncryptedData.Encrypt(
                authenticator.EncodeApplication(),
                sessionKey,
                KeyUsage.PaTgsReqAuthenticator),
        };

        return new KrbTgsReq
        {
            Body = body,
            PaData =
            [
                new KrbPaData
                {
                    Type = PaDataType.PA_TGS_REQ,
                    Value = apReq.EncodeApplication(),
                },
                .. paData ?? [],
            ],
        };
    }

    private static async Task AssertError(ReadOnlyMemory<byte> reply, KerberosErrorCode expected)
    {
        await Assert.That(reply.Span[0]).IsEqualTo((byte)0x7E);
        await Assert.That(KrbError.DecodeApplication(reply).ErrorCode).IsEqualTo(expected);
    }

    [Test]
    public async Task RejectsTimestampOutsideSkew()
    {
        TestRealm realm = new();
        KerberosKey key = realm.User.State.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96)!;

        ReadOnlyMemory<byte> reply = realm.Send(NewAsReq("user", key, s_start.AddMinutes(-6)));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_SKEW);
    }

    [Test]
    public async Task RejectsWrongProtocolVersion()
    {
        TestRealm realm = new();
        KrbAsReq request = NewAsReq("user", null, s_start);
        request.ProtocolVersionNumber = 4;

        await AssertError(realm.Send(request), KerberosErrorCode.KRB_AP_ERR_BADVERSION);
    }

    [Test]
    public async Task RejectsUnsupportedMessage()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, _) = realm.GetTgt();
        KrbApReq apReq = new()
        {
            Ticket = tgt.Ticket,
            Authenticator = tgt.EncryptedPart,
        };

        ReadOnlyMemory<byte> reply = realm.Processor.Process(apReq.EncodeApplication());

        await AssertError(reply, KerberosErrorCode.KRB_ERR_GENERIC);
        await Assert.That(KrbError.DecodeApplication(reply).EText).StartsWith("Failed to process request: ");
    }

    [Test]
    public async Task AcceptsRequestWithoutPaData()
    {
        TestRealm realm = new();
        realm.Store.Create(["nopreauth"], TestKdc.ToSecureString(TestKdc.Password),
            flags: ObolPrincipalFlag.DoesNotRequirePreAuth);

        ReadOnlyMemory<byte> reply = realm.Send(NewAsReq("nopreauth", null, s_start));

        KrbAsRep asRep = KrbAsRep.DecodeApplication(reply);
        await Assert.That(asRep.CName.Name).IsEquivalentTo(["nopreauth"]);

        KerberosKey key = realm.Store.Find(["nopreauth"])!.State.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96)!;
        KrbEncAsRepPart part = DecryptAsRep(asRep, key);
        KrbEncTicketPart ticket = TestKdc.DecryptTicket(asRep.Ticket, realm.Store.Krbtgt);
        await Assert.That(part.Nonce).IsEqualTo(1234);
        await Assert.That(part.Flags).IsEqualTo(ticket.Flags);
        await Assert.That(ticket.Flags).IsEqualTo(TicketFlags.Initial);
    }

    [Test]
    public async Task SendsSaltOfPrincipalNameForAlias()
    {
        TestRealm realm = new();
        ObolPrincipal web = realm.Store.Create(
            ["HTTP", "web"],
            TestKdc.ToSecureString(TestKdc.Password),
            flags: ObolPrincipalFlag.DoesNotRequirePreAuth,
            aliases: [["web"]]);

        ReadOnlyMemory<byte> reply = realm.Send(NewAsReq("web", null, s_start));

        // The client derives the key with the default salt of the name it sent unless the reply has a salt.
        KrbAsRep asRep = KrbAsRep.DecodeApplication(reply);
        KrbPaData paData = asRep.PaData.Single(p => p.Type == PaDataType.PA_ETYPE_INFO2);
        KrbETypeInfo2Entry entry = KrbETypeInfo2.Decode(paData.Value).ETypeInfo.Single();
        await Assert.That(entry.EType).IsEqualTo(EncryptionType.AES256_CTS_HMAC_SHA1_96);
        await Assert.That(entry.Salt).IsEqualTo("EXAMPLE.TESTHTTPweb");
        await Assert.That(entry.Salt).IsEqualTo(web.State.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96)!.Salt);
    }

    [Test]
    public async Task ServiceTicketKeepsAuthTimeOfTgt()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        realm.Clock.Now = s_start.AddMinutes(30);

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, realm.Clock.Now));

        // Without an authenticator subkey the reply is encrypted with the TGT session key.
        KrbTgsRep tgsRep = KrbTgsRep.DecodeApplication(reply);
        KrbEncTgsRepPart part = DecryptTgsRep(tgsRep, tgtPart);
        KrbEncTicketPart ticket = TestKdc.DecryptTicket(tgsRep.Ticket, realm.Service);
        await Assert.That(part.AuthTime).IsEqualTo(tgtPart.AuthTime);
        await Assert.That(ticket.AuthTime).IsEqualTo(tgtPart.AuthTime);
        await Assert.That(ticket.StartTime).IsEqualTo(realm.Clock.Now);

        // The request asked for a ticket until 1h30, the TGT ends at 1h so the service ticket ends with it.
        await Assert.That(ticket.EndTime).IsEqualTo(tgtPart.EndTime);
        await Assert.That(part.EndTime).IsEqualTo(tgtPart.EndTime);

        // MIT rejects a reply whose nonce or flags differ from the ticket, the Kerberos.NET client does not check.
        await Assert.That(part.Nonce).IsEqualTo(5678);
        await Assert.That(part.Flags).IsEqualTo(ticket.Flags);
        await Assert.That(part.SName.Name).IsEquivalentTo(ServiceName.Split('/'));
    }

    [Test]
    public async Task IssuesTicketForNameWithMoreThanTwoComponents()
    {
        TestRealm realm = new();
        ObolPrincipal service = realm.Store.Create(["HTTP", "web.example.test", "svc"], password: null,
            flags: ObolPrincipalFlag.None);
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start, "HTTP/web.example.test/svc"));

        KrbTgsRep tgsRep = KrbTgsRep.DecodeApplication(reply);
        await Assert.That(tgsRep.Ticket.SName.Name).IsEquivalentTo(["HTTP", "web.example.test", "svc"]);
        await Assert.That(TestKdc.DecryptTicket(tgsRep.Ticket, service).CName.Name).IsEquivalentTo(["user"]);
    }

    [Test]
    public async Task FindsComponentWithAtBeforeStrippingRealm()
    {
        TestRealm realm = new();
        ObolPrincipal principal = realm.Store.Create(["user@EXAMPLE.TEST"], TestKdc.ToSecureString(TestKdc.Password),
            flags: ObolPrincipalFlag.DoesNotRequirePreAuth);

        // The user principal requires pre-auth so an AS-REP means the escaped name was found.
        ReadOnlyMemory<byte> reply = realm.Send(NewAsReq("user@EXAMPLE.TEST", null, s_start));

        await Assert.That(principal.Name).IsEqualTo(@"user\@EXAMPLE.TEST");
        await Assert.That(KrbAsRep.DecodeApplication(reply).CName.Name).IsEquivalentTo(["user@EXAMPLE.TEST"]);
    }

    [Test]
    public async Task StripsRealmFromSingleComponent()
    {
        TestRealm realm = new();

        ReadOnlyMemory<byte> reply = realm.Send(NewAsReq("user@example.test", null, s_start));

        await AssertError(reply, KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RejectsMissingClientName(bool emptyName)
    {
        TestRealm realm = new();
        KrbAsReq request = NewAsReq("user", null, s_start);
        request.Body.CName = emptyName ? Name() : null;

        await AssertError(realm.Send(request), KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
    }

    [Test]
    public async Task RejectsTgsReqWithoutServiceEncryptionType()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            configureBody: b => b.EType = [EncryptionType.AES256_CTS_HMAC_SHA384_192]));

        await AssertError(reply, KerberosErrorCode.KDC_ERR_ETYPE_NOSUPP);
    }

    [Test]
    public async Task IssuesUserToUserTicket()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        // The additional ticket is the TGT of the service, here the user's own, its session key encrypts the ticket.
        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start, service: "user",
            configureBody: b =>
            {
                b.KdcOptions |= KdcOptions.EncTktInSkey;
                b.AdditionalTickets = [tgt.Ticket];
            }));

        KrbTgsRep tgsRep = KrbTgsRep.DecodeApplication(reply);
        KrbEncTicketPart ticket = tgsRep.Ticket.EncryptedPart.Decrypt(
            tgtPart.Key.AsKey(),
            KeyUsage.Ticket,
            b => KrbEncTicketPart.DecodeApplication(b));
        await Assert.That(ticket.CName.Name).IsEquivalentTo(["user"]);
        await Assert.That(tgsRep.Ticket.SName.Name).IsEquivalentTo(["user"]);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RejectsUserToUserWithoutTgt(bool serviceTicket)
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        KrbTicket[] additionalTickets = serviceTicket
            ? [KrbTgsRep.DecodeApplication(realm.Send(NewTgsReq(tgt, tgtPart, s_start))).Ticket]
            : [];

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start, service: "user",
            configureBody: b =>
            {
                b.KdcOptions |= KdcOptions.EncTktInSkey;
                b.AdditionalTickets = additionalTickets;
            }));

        await AssertError(reply, KerberosErrorCode.KDC_ERR_BADOPTION);
    }

    [Test]
    public async Task RejectsRenewAfterRenewTill()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt(b =>
        {
            b.KdcOptions |= KdcOptions.Renewable;
            b.RTime = b.Till.AddMinutes(1);
        });

        // The TGT has ended but is within the clock skew, its renew-till has passed.
        realm.Clock.Now = tgtPart.RenewTill!.Value.AddMinutes(1);
        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, realm.Clock.Now, service: $"krbtgt/{Realm}",
            configureBody: b => b.KdcOptions |= KdcOptions.Renew));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_TKT_EXPIRED);
        await Assert.That(KrbError.DecodeApplication(reply).EText)
            .IsEqualTo("The renewable lifetime of the ticket has passed");
    }

    [Test]
    public async Task RejectsTgtThatFailsToDecrypt()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        byte[] cipher = tgt.Ticket.EncryptedPart.Cipher.ToArray();
        cipher[^1] ^= 0xFF;
        KrbTicket modified = new()
        {
            Realm = tgt.Ticket.Realm,
            SName = tgt.Ticket.SName,
            EncryptedPart = new KrbEncryptedData
            {
                EType = tgt.Ticket.EncryptedPart.EType,
                KeyVersionNumber = tgt.Ticket.EncryptedPart.KeyVersionNumber,
                Cipher = cipher,
            },
        };

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start, ticket: modified));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_BAD_INTEGRITY);
    }

    [Test]
    public async Task RejectsTgtNotYetValid()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        realm.Clock.Now = s_start.AddMinutes(-6);

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, realm.Clock.Now));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_TKT_NYV);
    }

    [Test]
    public async Task RejectsChecksumTypeNotMatchingKey()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        // The TGT session key is AES256 SHA1, a valid SHA384 checksum made with it is still rejected.
        KerberosKey sessionKey = tgtPart.Key.AsKey();
        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            checksum: b => KrbChecksum.Create(b.Encode(), sessionKey, KeyUsage.PaTgsReqChecksum,
                ChecksumType.HMAC_SHA384_192_AES256)));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_INAPP_CKSUM);
        await Assert.That(KrbError.DecodeApplication(reply).EText).IsEqualTo(
            "The checksum type HMAC_SHA384_192_AES256 of the request body is not the checksum type of the session " +
            "key type AES256_CTS_HMAC_SHA1_96");
    }

    [Test]
    public async Task RejectsTgtWithUnsupportedSessionKey()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        // A TGT this KDC did not issue, made with the krbtgt key, with an RC4 session key.
        KerberosKey krbtgtKey = realm.Store.Krbtgt.State.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96)!;
        KrbEncTicketPart forgedPart = KrbEncTicketPart.DecodeApplication(tgt.Ticket.EncryptedPart.Decrypt(
            krbtgtKey,
            KeyUsage.Ticket,
            b => b));
        forgedPart.Key = new KrbEncryptionKey
        {
            EType = EncryptionType.RC4_HMAC_NT,
            KeyValue = new byte[16],
        };
        KrbAsRep forged = new()
        {
            CName = tgt.CName,
            CRealm = tgt.CRealm,
            Ticket = new KrbTicket
            {
                Realm = tgt.Ticket.Realm,
                SName = tgt.Ticket.SName,
                EncryptedPart = KrbEncryptedData.Encrypt(forgedPart.EncodeApplication(), krbtgtKey, KeyUsage.Ticket),
            },
        };
        KrbEncAsRepPart forgedRepPart = new() { Key = forgedPart.Key };

        // An AES checksum type so the request gets past the supported type check to the session key type.
        KerberosKey rc4Key = forgedPart.Key.AsKey();
        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(forged, forgedRepPart, s_start,
            checksum: b => KrbChecksum.Create(b.Encode(), rc4Key, KeyUsage.PaTgsReqChecksum,
                ChecksumType.HMAC_SHA1_96_AES256)));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_INAPP_CKSUM);
    }

    [Test]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96)]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96)]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128)]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192)]
    public async Task AcceptsBodyChecksumForSessionKeyType(EncryptionType sessionEType)
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt(b => b.EType = [sessionEType]);

        // The checksum type is the one for the TGT session key type.
        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start));

        await Assert.That(tgtPart.Key.EType).IsEqualTo(sessionEType);
        await Assert.That(reply.Span[0]).IsEqualTo((byte)0x6D);
    }

    [Test]
    public async Task RejectsModifiedBody()
    {
        TestRealm realm = new();
        realm.Store.Create(["HTTP", "other.example.test"], password: null, flags: ObolPrincipalFlag.None);
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        KrbTgsReq request = NewTgsReq(tgt, tgtPart, s_start);

        // A replayed authenticator cannot be used to ask for a different service.
        request.Body.SName = Name("HTTP", "other.example.test");

        await AssertError(realm.Send(request), KerberosErrorCode.KRB_AP_ERR_MODIFIED);
    }

    [Test]
    public async Task RejectsMissingChecksum()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start, checksum: _ => null));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_INAPP_CKSUM);
    }

    [Test]
    [Arguments(1, KerberosErrorCode.KRB_AP_ERR_INAPP_CKSUM)]
    [Arguments(7, KerberosErrorCode.KRB_AP_ERR_INAPP_CKSUM)]
    [Arguments(14, KerberosErrorCode.KRB_AP_ERR_INAPP_CKSUM)]
    [Arguments(8, KerberosErrorCode.KDC_ERR_SUMTYPE_NOSUPP)]
    [Arguments(-138, KerberosErrorCode.KDC_ERR_SUMTYPE_NOSUPP)]
    [Arguments(9999, KerberosErrorCode.KDC_ERR_SUMTYPE_NOSUPP)]
    public async Task RejectsUnsupportedChecksumType(int type, KerberosErrorCode expected)
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        // RFC 4120 3.3.2 an unkeyed checksum like CRC32, RSA-MD5 or SHA-1 is inappropriate, other unknown types,
        // like RSA-MD5-DES and the RC4 HMAC-MD5, are not supported.
        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            checksum: _ => new KrbChecksum
            {
                Type = (ChecksumType)type,
                Checksum = new byte[16],
            }));

        await AssertError(reply, expected);
    }

    [Test]
    public async Task RejectsChecksumWithWrongKey()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        KerberosKey otherKey = KrbEncryptionKey.Generate(EncryptionType.AES256_CTS_HMAC_SHA1_96).AsKey();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            checksum: b => KrbChecksum.Create(b.Encode(), otherKey, KeyUsage.PaTgsReqChecksum)));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_MODIFIED);
    }

    [Test]
    public async Task RejectsAuthenticatorOutsideSkew()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start.AddMinutes(6)));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_SKEW);
    }

    [Test]
    public async Task RejectsAuthenticatorForOtherClient()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            authenticatorCName: Name("admin")));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_BADMATCH);
    }

    [Test]
    public async Task RejectsExpiredTgt()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        realm.Clock.Now = tgtPart.EndTime.AddMinutes(6);

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, realm.Clock.Now));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_TKT_EXPIRED);
    }

    [Test]
    public async Task RejectsServiceTicketAsTgt()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        KrbTgsRep serviceTicket = KrbTgsRep.DecodeApplication(realm.Send(NewTgsReq(tgt, tgtPart, s_start)));

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start, ticket: serviceTicket.Ticket));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_NOT_US);
    }

    [Test]
    public async Task RejectsTgtAfterKrbtgtKeyChange()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        realm.Store.Update(realm.Store.Krbtgt, password: null, newRandomKey: true);

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_BADKEYVER);
    }

    [Test]
    public async Task RejectsTgtAfterKrbtgtKvnoChange()
    {
        // Renumbering the keys without changing them still rejects TGTs issued with the old kvno.
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        realm.Store.Update(realm.Store.Krbtgt, kvno: 2);

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_BADKEYVER);
    }

    private static readonly KrbHostAddress s_tgtAddress = new()
    {
        AddressType = AddressType.IPv4,
        Address = new byte[] { 192, 0, 2, 1 },
    };

    /// <summary>Requests a forwarded TGT and returns it as an AS-REP so it can be used for another request.</summary>
    private static (KrbAsRep Tgt, KrbEncAsRepPart Part, KrbEncTicketPart Ticket) GetForwardedTgt(
        TestRealm realm,
        KrbAsRep tgt,
        KrbEncAsRepPart tgtPart,
        Action<KrbKdcReqBody>? configureBody = null)
    {
        KrbTgsRep reply = KrbTgsRep.DecodeApplication(realm.Send(NewTgsReq(tgt, tgtPart, realm.Clock.Now,
            service: $"krbtgt/{Realm}",
            configureBody: b =>
            {
                b.KdcOptions |= KdcOptions.Forwarded;
                configureBody?.Invoke(b);
            })));
        KrbEncTgsRepPart part = DecryptTgsRep(reply, tgtPart);
        KrbAsRep forwarded = new()
        {
            CName = reply.CName,
            CRealm = reply.CRealm,
            Ticket = reply.Ticket,
        };
        return (forwarded, new KrbEncAsRepPart { Key = part.Key, EndTime = part.EndTime, Flags = part.Flags },
            TestKdc.DecryptTicket(reply.Ticket, realm.Store.Krbtgt));
    }

    [Test]
    public async Task IssuesForwardedTgt()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt(b =>
        {
            b.KdcOptions |= KdcOptions.Forwardable;
            b.Addresses = [s_tgtAddress];
        });
        KrbHostAddress requested = new() { AddressType = AddressType.IPv4, Address = new byte[] { 192, 0, 2, 2 } };

        (_, KrbEncAsRepPart part, KrbEncTicketPart ticket) = GetForwardedTgt(realm, tgt, tgtPart, b =>
        {
            b.KdcOptions |= KdcOptions.Forwardable;
            b.Addresses = [requested];
        });

        // RFC 4120 2.6 the forwarded ticket has the addresses of the request instead of the TGT.
        await Assert.That(ticket.Flags).IsEqualTo(
            TicketFlags.Forwarded | TicketFlags.Forwardable | TicketFlags.PreAuthenticated);
        await Assert.That(part.Flags).IsEqualTo(ticket.Flags);
        await Assert.That(ticket.CAddr.Single().Address.ToArray()).IsEquivalentTo(new byte[] { 192, 0, 2, 2 });
    }

    [Test]
    public async Task IssuesForwardedTgtWithoutAddresses()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt(b =>
        {
            b.KdcOptions |= KdcOptions.Forwardable;
            b.Addresses = [s_tgtAddress];
        });

        (_, _, KrbEncTicketPart ticket) = GetForwardedTgt(realm, tgt, tgtPart);

        // Without FORWARDABLE in the request the forwarded ticket cannot be forwarded again.
        await Assert.That(ticket.Flags).IsEqualTo(TicketFlags.Forwarded | TicketFlags.PreAuthenticated);
        await Assert.That(ticket.CAddr ?? []).IsEmpty();
    }

    [Test]
    public async Task RejectsForwardedFromNonForwardableTgt()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start, service: $"krbtgt/{Realm}",
            configureBody: b => b.KdcOptions |= KdcOptions.Forwarded));

        await AssertError(reply, KerberosErrorCode.KDC_ERR_BADOPTION);
        await Assert.That(KrbError.DecodeApplication(reply).EText).IsEqualTo("The ticket is not forwardable");
    }

    [Test]
    public async Task KeepsForwardedFromForwardedTgt()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt(b =>
            b.KdcOptions |= KdcOptions.Forwardable | KdcOptions.Renewable);
        (KrbAsRep forwarded, KrbEncAsRepPart forwardedPart, _) = GetForwardedTgt(realm, tgt, tgtPart,
            b => b.KdcOptions |= KdcOptions.Renewable);

        // RFC 4120 2.6 tickets issued from a forwarded TGT are forwarded too, including a renewal of it.
        KrbTgsRep serviceReply = KrbTgsRep.DecodeApplication(realm.Send(NewTgsReq(forwarded, forwardedPart,
            s_start)));
        KrbTgsRep renewReply = KrbTgsRep.DecodeApplication(realm.Send(NewTgsReq(forwarded, forwardedPart, s_start,
            service: $"krbtgt/{Realm}",
            configureBody: b => b.KdcOptions |= KdcOptions.Renew)));

        KrbEncTicketPart serviceTicket = TestKdc.DecryptTicket(serviceReply.Ticket, realm.Service);
        KrbEncTicketPart renewed = TestKdc.DecryptTicket(renewReply.Ticket, realm.Store.Krbtgt);
        await Assert.That(serviceTicket.Flags).IsEqualTo(TicketFlags.Forwarded | TicketFlags.PreAuthenticated);
        await Assert.That(renewed.Flags).IsEqualTo(
            TicketFlags.Forwarded | TicketFlags.Renewable | TicketFlags.PreAuthenticated);
    }

    [Test]
    public async Task IssuesNotDelegatedClientNonForwardableTgt()
    {
        TestRealm realm = new();
        realm.Store.Update(realm.User, flags: ObolPrincipalFlag.NotDelegated);

        // MS-SAMR USER_NOT_DELEGATED the forwardable option is ignored rather than rejected.
        (_, KrbEncAsRepPart tgtPart) = realm.GetTgt(b => b.KdcOptions |= KdcOptions.Forwardable);

        await Assert.That(tgtPart.Flags.HasFlag(TicketFlags.Forwardable)).IsFalse();
    }

    [Test]
    public async Task AppliesNotDelegatedSetAfterTgtWasIssued()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt(b =>
            b.KdcOptions |= KdcOptions.Forwardable | KdcOptions.Renewable);
        realm.Store.Update(realm.User, flags: ObolPrincipalFlag.NotDelegated);

        ReadOnlyMemory<byte> forwardReply = realm.Send(NewTgsReq(tgt, tgtPart, s_start, service: $"krbtgt/{Realm}",
            configureBody: b => b.KdcOptions |= KdcOptions.Forwarded));
        KrbTgsRep serviceReply = KrbTgsRep.DecodeApplication(realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            configureBody: b => b.KdcOptions |= KdcOptions.Forwardable)));
        KrbTgsRep renewReply = KrbTgsRep.DecodeApplication(realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            service: $"krbtgt/{Realm}",
            configureBody: b => b.KdcOptions |= KdcOptions.Renew)));

        await AssertError(forwardReply, KerberosErrorCode.KDC_ERR_BADOPTION);
        await Assert.That(KrbError.DecodeApplication(forwardReply).EText)
            .IsEqualTo("The client principal cannot be delegated");
        KrbEncTicketPart serviceTicket = TestKdc.DecryptTicket(serviceReply.Ticket, realm.Service);
        KrbEncTicketPart renewed = TestKdc.DecryptTicket(renewReply.Ticket, realm.Store.Krbtgt);
        await Assert.That(serviceTicket.Flags.HasFlag(TicketFlags.Forwardable)).IsFalse();
        await Assert.That(renewed.Flags.HasFlag(TicketFlags.Forwardable)).IsFalse();
    }

    [Test]
    public async Task SetsOkAsDelegateForTrustedService()
    {
        TestRealm realm = new();
        realm.Store.Update(realm.Service, flags: ObolPrincipalFlag.TrustedForDelegation);
        KerberosKey key = realm.User.State.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96)!;
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        KrbTgsRep tgsReply = KrbTgsRep.DecodeApplication(realm.Send(NewTgsReq(tgt, tgtPart, s_start)));
        KrbAsRep asReply = KrbAsRep.DecodeApplication(realm.Send(NewAsReq("user", key, s_start,
            sname: Name(ServiceName.Split('/')))));

        // MS-SAMR USER_TRUSTED_FOR_DELEGATION, the flag is in the ticket and the reply, the TGT does not get it.
        KrbEncTicketPart tgsTicket = TestKdc.DecryptTicket(tgsReply.Ticket, realm.Service);
        KrbEncTicketPart asTicket = TestKdc.DecryptTicket(asReply.Ticket, realm.Service);
        await Assert.That(tgsTicket.Flags.HasFlag(TicketFlags.OkAsDelegate)).IsTrue();
        await Assert.That(DecryptTgsRep(tgsReply, tgtPart).Flags.HasFlag(TicketFlags.OkAsDelegate)).IsTrue();
        await Assert.That(asTicket.Flags.HasFlag(TicketFlags.OkAsDelegate)).IsTrue();
        await Assert.That(tgtPart.Flags.HasFlag(TicketFlags.OkAsDelegate)).IsFalse();
    }

    [Test]
    [Arguments(ObolPrincipalFlag.None, 0x10u)]
    [Arguments(ObolPrincipalFlag.DoesNotRequirePreAuth, 0x10010u)]
    [Arguments(ObolPrincipalFlag.NotDelegated, 0x4010u)]
    [Arguments(ObolPrincipalFlag.TrustedForDelegation, 0x2010u)]
    [Arguments(ObolPrincipalFlag.NotDelegated | ObolPrincipalFlag.TrustedForDelegation, 0x6010u)]
    public async Task SetsPacUserAccountControl(ObolPrincipalFlag flags, uint expected)
    {
        TestRealm realm = new();
        realm.Store.Update(realm.User, flags: flags);

        // MS-SAMR USER_* codes, USER_NORMAL_ACCOUNT is always set.
        PrivilegedAttributeCertificate pac = new KdcPrincipal(realm.User).GeneratePac(s_start);

        await Assert.That((uint)pac.LogonInfo.UserAccountControl).IsEqualTo(expected);
    }

    [Test]
    public async Task RejectsRenewForOtherService()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt(b => b.KdcOptions |= KdcOptions.Renewable);

        // RFC 4120 3.3.2 a renewal is for the service of the ticket being renewed, only TGTs can be renewed.
        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            configureBody: b => b.KdcOptions |= KdcOptions.Renew));

        await AssertError(reply, KerberosErrorCode.KDC_ERR_SERVER_NOMATCH);
        await Assert.That(KrbError.DecodeApplication(reply).SName.Name).IsEquivalentTo(ServiceName.Split('/'));
    }

    [Test]
    public async Task RejectsTimestampWithoutClientKey()
    {
        TestRealm realm = new();
        // The user only has SHA-1 keys.
        KerberosKey key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA256_128).AsKey();

        ReadOnlyMemory<byte> reply = realm.Send(NewAsReq("user", key, s_start));

        await AssertError(reply, KerberosErrorCode.KDC_ERR_PREAUTH_FAILED);
        await Assert.That(KrbError.DecodeApplication(reply).EText)
            .IsEqualTo("The principal has no key for the encryption type AES128_CTS_HMAC_SHA256_128");
    }

    [Test]
    public async Task RejectsTgsReqWithoutPaTgsReq()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        KrbTgsReq request = NewTgsReq(tgt, tgtPart, s_start);
        request.PaData = [PacRequest(true)];

        await AssertError(realm.Send(request), KerberosErrorCode.KDC_ERR_PADATA_TYPE_NOSUPP);
    }

    [Test]
    public async Task RejectsTgsReqForOtherRealm()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            configureBody: b => b.Realm = "OTHER.TEST"));

        await AssertError(reply, KerberosErrorCode.KDC_ERR_WRONG_REALM);
    }

    [Test]
    public async Task ReportsRequestedServiceInError()
    {
        TestRealm realm = new();
        KrbPrincipalName unknown = Name("HTTP", "nope.example.test");
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        KrbError asError = KrbError.DecodeApplication(realm.Send(NewAsReq("user", null, s_start, sname: unknown)));
        KrbError tgsError = KrbError.DecodeApplication(realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            "HTTP/nope.example.test")));
        KrbError clientError = KrbError.DecodeApplication(realm.Send(NewAsReq("nobody", null, s_start)));

        // The sname of the error is the service that was asked for, other errors name the krbtgt.
        await Assert.That(asError.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN);
        await Assert.That(asError.SName.Name).IsEquivalentTo(["HTTP", "nope.example.test"]);
        await Assert.That(tgsError.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN);
        await Assert.That(tgsError.SName.Name).IsEquivalentTo(["HTTP", "nope.example.test"]);
        await Assert.That(clientError.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
        await Assert.That(clientError.SName.Name).IsEquivalentTo(["krbtgt", Realm]);
        await Assert.That(clientError.Realm).IsEqualTo(Realm);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task GrantsForwardableOnlyFromForwardableTgt(bool tgtForwardable)
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt(b =>
        {
            if (tgtForwardable)
            {
                b.KdcOptions |= KdcOptions.Forwardable;
            }
        });

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            configureBody: b => b.KdcOptions |= KdcOptions.Forwardable));

        KrbEncTicketPart ticket = TestKdc.DecryptTicket(KrbTgsRep.DecodeApplication(reply).Ticket, realm.Service);
        await Assert.That(tgtPart.Flags.HasFlag(TicketFlags.Forwardable)).IsEqualTo(tgtForwardable);
        await Assert.That(ticket.Flags.HasFlag(TicketFlags.Forwardable)).IsEqualTo(tgtForwardable);
    }

    [Test]
    public async Task IssuesServiceTicketFromAsReq()
    {
        TestRealm realm = new();
        KerberosKey key = realm.User.State.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96)!;

        // An AS-REQ can ask for any service, like kadmin/changepw, not only the krbtgt.
        ReadOnlyMemory<byte> reply = realm.Send(NewAsReq("user", key, s_start, sname: Name(ServiceName.Split('/'))));

        KrbAsRep asRep = KrbAsRep.DecodeApplication(reply);
        KrbEncAsRepPart part = DecryptAsRep(asRep, key);
        KrbEncTicketPart ticket = TestKdc.DecryptTicket(asRep.Ticket, realm.Service);
        await Assert.That(asRep.Ticket.SName.Name).IsEquivalentTo(ServiceName.Split('/'));
        await Assert.That(asRep.Ticket.EncryptedPart.EType).IsEqualTo(EncryptionType.AES256_CTS_HMAC_SHA1_96);
        await Assert.That(ticket.Flags).IsEqualTo(TicketFlags.Initial | TicketFlags.PreAuthenticated);
        await Assert.That(ticket.CName.Name).IsEquivalentTo(["user"]);
        await Assert.That(part.SName.Name).IsEquivalentTo(ServiceName.Split('/'));
        await Assert.That(HasPac(ticket)).IsTrue();
    }

    [Test]
    public async Task ListsClientKeysInPreAuthRequiredError()
    {
        TestRealm realm = new();
        KrbAsReq request = NewAsReq("user", null, s_start);
        // A type the user has no key for, a repeated type, and the user's types in the client's order.
        request.Body.EType =
        [
            EncryptionType.AES256_CTS_HMAC_SHA384_192,
            EncryptionType.AES128_CTS_HMAC_SHA1_96,
            EncryptionType.AES128_CTS_HMAC_SHA1_96,
            EncryptionType.AES256_CTS_HMAC_SHA1_96,
        ];

        KrbError error = KrbError.DecodeApplication(realm.Send(request));

        // RFC 4120 5.2.7.5 the entries are in the client's order of preference, MIT uses the first it supports.
        await Assert.That(error.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED);
        KrbMethodData methodData = KrbMethodData.Decode(error.EData!.Value);
        await Assert.That(methodData.MethodData.Select(p => p.Type))
            .IsEquivalentTo([PaDataType.PA_ENC_TIMESTAMP, PaDataType.PA_ETYPE_INFO2]);
        KrbETypeInfo2Entry[] entries = KrbETypeInfo2.Decode(methodData.MethodData[1].Value).ETypeInfo;
        await Assert.That(entries.Select(e => e.EType))
            .IsEquivalentTo([EncryptionType.AES128_CTS_HMAC_SHA1_96, EncryptionType.AES256_CTS_HMAC_SHA1_96]);
        await Assert.That(entries.Select(e => e.Salt)).IsEquivalentTo(["EXAMPLE.TESTuser", "EXAMPLE.TESTuser"]);
    }

    [Test]
    [Arguments(null, null, true)]
    [Arguments(true, null, true)]
    [Arguments(false, null, false)]
    [Arguments(false, true, true)]
    [Arguments(true, false, false)]
    public async Task IncludesPacWhenRequested(bool? asRequest, bool? tgsRequest, bool expected)
    {
        TestRealm realm = new();
        KerberosKey key = realm.User.State.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96)!;

        // Like AD the PAC is included unless PA-PAC-REQUEST says not to, a TGS without one follows the TGT.
        KrbAsReq asReq = NewAsReq("user", key, s_start, paData: asRequest is bool a ? [PacRequest(a)] : null);
        KrbAsRep tgt = KrbAsRep.DecodeApplication(realm.Send(asReq));
        KrbEncAsRepPart tgtPart = DecryptAsRep(tgt, key);
        await Assert.That(HasPac(TestKdc.DecryptTicket(tgt.Ticket, realm.Store.Krbtgt))).IsEqualTo(asRequest ?? true);

        KrbTgsReq tgsReq = NewTgsReq(tgt, tgtPart, s_start, paData: tgsRequest is bool t ? [PacRequest(t)] : null);
        KrbTgsRep tgsRep = KrbTgsRep.DecodeApplication(realm.Send(tgsReq));
        await Assert.That(HasPac(TestKdc.DecryptTicket(tgsRep.Ticket, realm.Service))).IsEqualTo(expected);
    }

    [Test]
    [Arguments(new[] { EncryptionType.AES256_CTS_HMAC_SHA1_96, EncryptionType.AES128_CTS_HMAC_SHA1_96 }, 0x18u)]
    [Arguments(new[] { EncryptionType.AES128_CTS_HMAC_SHA256_128 }, 0x40u)]
    [Arguments(new[] { EncryptionType.AES256_CTS_HMAC_SHA384_192 }, 0x80u)]
    [Arguments(new[] { EncryptionType.AES256_CTS_HMAC_SHA384_192, EncryptionType.AES256_CTS_HMAC_SHA1_96 }, 0x90u)]
    public async Task EncodesSupportedEncryptionTypesOfService(EncryptionType[] etypes, uint expected)
    {
        TestRealm realm = new();
        realm.Store.Create(["HTTP", "sha"], null, ObolPrincipalFlag.None,
            [.. etypes.Select(e => (ObolEncryptionType)e)]);
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start, "HTTP/sha",
            configureBody: b => b.EType = etypes));

        // MS-KILE 2.2.7 the value is a little endian bit mask, the krbtgt has every type.
        KrbEncTgsRepPart part = DecryptTgsRep(KrbTgsRep.DecodeApplication(reply), tgtPart);
        await Assert.That(ReadSupportedEncryptionTypes(part)).IsEqualTo(expected);
        await Assert.That(ReadSupportedEncryptionTypes(tgtPart)).IsEqualTo(0xD8u);
    }

    private static uint ReadSupportedEncryptionTypes(KrbEncKdcRepPart part)
    {
        KrbPaData paData = part.EncryptedPaData!.MethodData.Single(p => p.Type == PaDataType.PA_SUPPORTED_ETYPES);
        return BinaryPrimitives.ReadUInt32LittleEndian(paData.Value.Span[..4]);
    }

    /// <summary>
    /// Re-encrypts the TGT with the krbtgt key after changing its decrypted part, like a TGT from a KDC with the key.
    /// </summary>
    private static KrbAsRep ReissueTgt(TestRealm realm, KrbAsRep tgt, Action<KrbEncTicketPart> change)
    {
        KerberosKey krbtgtKey = realm.Store.Krbtgt.State.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96)!;
        KrbEncTicketPart part = tgt.Ticket.EncryptedPart.Decrypt(
            krbtgtKey,
            KeyUsage.Ticket,
            b => KrbEncTicketPart.DecodeApplication(b));
        change(part);

        KrbEncryptedData encrypted = KrbEncryptedData.Encrypt(part.EncodeApplication(), krbtgtKey, KeyUsage.Ticket);
        encrypted.KeyVersionNumber = tgt.Ticket.EncryptedPart.KeyVersionNumber;
        return new KrbAsRep
        {
            CName = tgt.CName,
            CRealm = tgt.CRealm,
            Ticket = new KrbTicket
            {
                Realm = tgt.Ticket.Realm,
                SName = tgt.Ticket.SName,
                EncryptedPart = encrypted,
            },
        };
    }

    /// <summary>Copies the ticket with a different realm, name or encrypted part, the cipher is kept as is.</summary>
    private static KrbTicket CopyTicket(KrbTicket ticket, string? realm = null, KrbPrincipalName? sname = null,
        EncryptionType? etype = null, bool keepKvno = true) => new()
    {
        Realm = realm ?? ticket.Realm,
        SName = sname ?? ticket.SName,
        EncryptedPart = new KrbEncryptedData
        {
            EType = etype ?? ticket.EncryptedPart.EType,
            KeyVersionNumber = keepKvno ? ticket.EncryptedPart.KeyVersionNumber : null,
            Cipher = ticket.EncryptedPart.Cipher,
        },
    };

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task RejectsRequestTagOfOtherClass(bool asReq)
    {
        // The AS-REQ and TGS-REQ application tag numbers in the context specific class are not requests.
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        byte[] request = asReq
            ? NewAsReq("user", null, s_start).EncodeApplication().ToArray()
            : NewTgsReq(tgt, tgtPart, s_start).EncodeApplication().ToArray();
        request[0] = (byte)((request[0] & 0x3F) | 0x80);

        ReadOnlyMemory<byte> reply = realm.Processor.Process(request);

        await AssertError(reply, KerberosErrorCode.KRB_ERR_GENERIC);
        await Assert.That(KrbError.DecodeApplication(reply).EText).Contains("is not supported");
    }

    [Test]
    public async Task RejectsAsReqWithoutServiceEncryptionType()
    {
        // The client has a key for the requested type for the reply, the service does not for the session key.
        TestRealm realm = new();
        realm.Store.Create(["aes128"], password: null, flags: ObolPrincipalFlag.None,
            encryptionTypes: [ObolEncryptionType.Aes128Sha1]);
        KerberosKey key = realm.User.State.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96)!;
        KrbAsReq request = NewAsReq("user", key, s_start, sname: Name("aes128"));
        request.Body.EType = [EncryptionType.AES256_CTS_HMAC_SHA1_96];

        await AssertError(realm.Send(request), KerberosErrorCode.KDC_ERR_ETYPE_NOSUPP);
    }

    [Test]
    public async Task RejectsTgsReqWithoutPaData()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        KrbTgsReq request = NewTgsReq(tgt, tgtPart, s_start);
        request.PaData = null;

        await AssertError(realm.Send(request), KerberosErrorCode.KDC_ERR_PADATA_TYPE_NOSUPP);
    }

    [Test]
    public async Task RejectsTgtOfOtherRealm()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            ticket: CopyTicket(tgt.Ticket, realm: "OTHER.TEST")));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_NOT_US);
    }

    [Test]
    public async Task RejectsTicketForUnknownService()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            ticket: CopyTicket(tgt.Ticket, sname: Name("missing", Realm))));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_NOT_US);
    }

    [Test]
    public async Task RejectsTgtWithEncryptionTypeKrbtgtHasNoKeyFor()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            ticket: CopyTicket(tgt.Ticket, etype: EncryptionType.RC4_HMAC_NT)));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_BADKEYVER);
        await Assert.That(KrbError.DecodeApplication(reply).EText)
            .IsEqualTo("The krbtgt principal has no key for the encryption type RC4_HMAC_NT");
    }

    [Test]
    public async Task AcceptsTgtWithoutKvno()
    {
        // The kvno is optional in EncryptedData, without it the current krbtgt key is used.
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            ticket: CopyTicket(tgt.Ticket, keepKvno: false)));

        await Assert.That(reply.Span[0]).IsEqualTo((byte)0x6D);
    }

    [Test]
    public async Task RejectsAuthenticatorForOtherRealm()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        KrbAsRep otherRealm = new()
        {
            CName = tgt.CName,
            CRealm = "OTHER.TEST",
            Ticket = tgt.Ticket,
        };

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(otherRealm, tgtPart, s_start));

        await AssertError(reply, KerberosErrorCode.KRB_AP_ERR_BADMATCH);
    }

    [Test]
    public async Task RenewsTgtWithoutStartTime()
    {
        // The start time is optional, the auth time is the start of the ticket without it.
        TestRealm realm = new();
        (KrbAsRep issued, KrbEncAsRepPart tgtPart) = realm.GetTgt(b =>
        {
            b.KdcOptions |= KdcOptions.Renewable;
            b.RTime = b.Till.AddHours(4);
        });
        KrbAsRep tgt = ReissueTgt(realm, issued, p => p.StartTime = null);
        realm.Clock.Now = s_start.AddMinutes(30);

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, realm.Clock.Now, service: $"krbtgt/{Realm}",
            configureBody: b => b.KdcOptions |= KdcOptions.Renew));

        KrbEncTgsRepPart renewed = DecryptTgsRep(KrbTgsRep.DecodeApplication(reply), tgtPart);
        await Assert.That(renewed.StartTime).IsEqualTo(realm.Clock.Now);
        await Assert.That(renewed.EndTime).IsEqualTo(realm.Clock.Now + (tgtPart.EndTime - tgtPart.AuthTime));
    }

    [Test]
    public async Task RejectsUserToUserWithoutAdditionalTickets()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start, service: "user",
            configureBody: b =>
            {
                b.KdcOptions |= KdcOptions.EncTktInSkey;
                b.AdditionalTickets = null;
            }));

        await AssertError(reply, KerberosErrorCode.KDC_ERR_BADOPTION);
    }

    [Test]
    public async Task RejectsUserToUserTicketKrbtgtHasNoKeyFor()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start, service: "user",
            configureBody: b =>
            {
                b.KdcOptions |= KdcOptions.EncTktInSkey;
                b.AdditionalTickets = [CopyTicket(tgt.Ticket, etype: EncryptionType.RC4_HMAC_NT)];
            }));

        await AssertError(reply, KerberosErrorCode.KDC_ERR_BADOPTION);
        await Assert.That(KrbError.DecodeApplication(reply).EText)
            .IsEqualTo("The additional ticket is not a ticket granting ticket");
    }
}
