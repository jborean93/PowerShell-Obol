using System;
using System.Buffers.Binary;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
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
            User = Store.Create(["user"], TestKdc.ToSecureString(TestKdc.Password),
                flags: Kerberos.PacUserAccountControl.None);
            Service = Store.Create(ServiceName.Split('/'), password: null, flags: Kerberos.PacUserAccountControl.None);
        }

        public TestClock Clock { get; } = new();

        public PrincipalStore Store { get; }

        public KdcProcessor Processor { get; }

        public ObolPrincipal User { get; }

        public ObolPrincipal Service { get; }

        public ReadOnlyMemory<byte> Send(KrbAsReq request)
            => Processor.Process(request.EncodeApplication()).ReplyBytes;

        public ReadOnlyMemory<byte> Send(KrbTgsReq request)
            => Processor.Process(request.EncodeApplication()).ReplyBytes;

        /// <summary>Gets a TGT for the user with the session key from the decrypted reply.</summary>
        public (KrbAsRep Reply, KrbEncAsRepPart Part) GetTgt(Action<KrbKdcReqBody>? configureBody = null)
        {
            KerberosKey key = User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
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

    /// <summary>The unkeyed RSA-MD5 checksum of the body, like Windows sends.</summary>
    private static KrbChecksum RsaMd5Checksum(KrbKdcReqBody body) => new()
    {
        Type = (ChecksumType)7,
        Checksum = MD5.HashData(body.Encode().Span),
    };

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
        KrbPaData[]? paData = null,
        Action<KrbAuthenticator>? configureAuthenticator = null)
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
        configureAuthenticator?.Invoke(authenticator);
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

    /// <summary>Re-encrypts the TGT with the krbtgt key after changing its plaintext, like the KDC that issued it.
    /// </summary>
    private static KrbTicket ForgeTgt(TestRealm realm, KrbAsRep tgt, Action<KrbEncTicketPart> configure)
    {
        KrbEncTicketPart part = TestKdc.DecryptTicket(tgt.Ticket, realm.Store.Krbtgt);
        configure(part);
        KerberosKey key = realm.Store.Krbtgt.State.GetKey(tgt.Ticket.EncryptedPart.EType.ToObol())!;
        KrbEncryptedData encrypted = KrbEncryptedData.Encrypt(part.EncodeApplication(), key, KeyUsage.Ticket);
        encrypted.KeyVersionNumber = tgt.Ticket.EncryptedPart.KeyVersionNumber;
        return new KrbTicket
        {
            Realm = tgt.Ticket.Realm,
            SName = tgt.Ticket.SName,
            EncryptedPart = encrypted,
        };
    }

    [Test]
    public async Task RejectsTimestampOutsideSkew()
    {
        TestRealm realm = new();
        KerberosKey key = realm.User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;

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

        ReadOnlyMemory<byte> reply = realm.Processor.Process(apReq.EncodeApplication()).ReplyBytes;

        await AssertError(reply, KerberosErrorCode.KRB_ERR_GENERIC);
        await Assert.That(KrbError.DecodeApplication(reply).EText).StartsWith("Failed to process request: ");
    }

    [Test]
    public async Task AcceptsRequestWithoutPaData()
    {
        TestRealm realm = new();
        realm.Store.Create(["nopreauth"], TestKdc.ToSecureString(TestKdc.Password),
            flags: Kerberos.PacUserAccountControl.DontRequirePreAuth);

        ReadOnlyMemory<byte> reply = realm.Send(NewAsReq("nopreauth", null, s_start));

        KrbAsRep asRep = KrbAsRep.DecodeApplication(reply);
        await Assert.That(asRep.CName.Name).IsEquivalentTo(["nopreauth"]);

        KerberosKey key = realm.Store.Find(["nopreauth"])!.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
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
            flags: Kerberos.PacUserAccountControl.DontRequirePreAuth,
            aliases: [["web"]]);

        ReadOnlyMemory<byte> reply = realm.Send(NewAsReq("web", null, s_start));

        // The client derives the key with the default salt of the name it sent unless the reply has a salt.
        KrbAsRep asRep = KrbAsRep.DecodeApplication(reply);
        KrbPaData paData = asRep.PaData.Single(p => p.Type == PaDataType.PA_ETYPE_INFO2);
        KrbETypeInfo2Entry entry = KrbETypeInfo2.Decode(paData.Value).ETypeInfo.Single();
        await Assert.That(entry.EType).IsEqualTo(EncryptionType.AES256_CTS_HMAC_SHA1_96);
        await Assert.That(entry.Salt).IsEqualTo("EXAMPLE.TESTHTTPweb");
        await Assert.That(entry.Salt).IsEqualTo(web.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!.Salt);
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
            flags: Kerberos.PacUserAccountControl.None);
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
            flags: Kerberos.PacUserAccountControl.DontRequirePreAuth);

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
            "The checksum type HmacSha384Aes256 of the request body is not the checksum type of the session key type " +
            "Aes256Sha1");
    }

    [Test]
    public async Task RejectsTgtWithUnsupportedSessionKey()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        // A TGT this KDC did not issue, made with the krbtgt key, with an RC4 session key.
        KerberosKey krbtgtKey = realm.Store.Krbtgt.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
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
        realm.Store.Create(["HTTP", "other.example.test"], password: null, flags: Kerberos.PacUserAccountControl.None);
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
    [Arguments(2, KerberosErrorCode.KRB_AP_ERR_INAPP_CKSUM)]
    [Arguments(14, KerberosErrorCode.KRB_AP_ERR_INAPP_CKSUM)]
    [Arguments(8, KerberosErrorCode.KDC_ERR_SUMTYPE_NOSUPP)]
    [Arguments(-138, KerberosErrorCode.KDC_ERR_SUMTYPE_NOSUPP)]
    [Arguments(9999, KerberosErrorCode.KDC_ERR_SUMTYPE_NOSUPP)]
    public async Task RejectsUnsupportedChecksumType(int type, KerberosErrorCode expected)
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        // The unkeyed checksums other than RSA-MD5, CRC32, RSA-MD4 and SHA-1, are inappropriate, other unknown
        // types, like RSA-MD5-DES and the RC4 HMAC-MD5, are not supported.
        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            checksum: _ => new KrbChecksum
            {
                Type = (ChecksumType)type,
                Checksum = new byte[16],
            }));

        await AssertError(reply, expected);
    }

    [Test]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96)]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96)]
    public async Task AcceptsRsaMd5BodyChecksum(EncryptionType sessionEType)
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt(b => b.EType = [sessionEType]);

        // Windows sends an unkeyed RSA-MD5 checksum of the body whatever the session key type.
        ReadOnlyMemory<byte> reply = realm.Send(NewTgsReq(tgt, tgtPart, s_start, checksum: RsaMd5Checksum));

        await Assert.That(reply.Span[0]).IsEqualTo((byte)0x6D);
    }

    [Test]
    public async Task RejectsModifiedBodyWithRsaMd5Checksum()
    {
        TestRealm realm = new();
        realm.Store.Create(["HTTP", "other.example.test"], password: null, flags: Kerberos.PacUserAccountControl.None);
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        KrbTgsReq request = NewTgsReq(tgt, tgtPart, s_start, checksum: RsaMd5Checksum);

        request.Body.SName = Name("HTTP", "other.example.test");

        await AssertError(realm.Send(request), KerberosErrorCode.KRB_AP_ERR_MODIFIED);
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
        realm.Store.Update(realm.User, flags: Kerberos.PacUserAccountControl.NotDelegated);

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
        realm.Store.Update(realm.User, flags: Kerberos.PacUserAccountControl.NotDelegated);

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
        realm.Store.Update(realm.Service, flags: Kerberos.PacUserAccountControl.TrustedForDelegation);
        KerberosKey key = realm.User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
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
    [Arguments(Kerberos.PacUserAccountControl.None, 0x10u)]
    [Arguments(Kerberos.PacUserAccountControl.DontRequirePreAuth, 0x10010u)]
    [Arguments(Kerberos.PacUserAccountControl.NotDelegated, 0x4010u)]
    [Arguments(Kerberos.PacUserAccountControl.TrustedForDelegation, 0x2010u)]
    [Arguments(
        Kerberos.PacUserAccountControl.NotDelegated | Kerberos.PacUserAccountControl.TrustedForDelegation,
        0x6010u)]
    [Arguments(Kerberos.PacUserAccountControl.NoAuthDataRequired, 0x80010u)]
    public async Task SetsPacUserAccountControl(Kerberos.PacUserAccountControl flags, uint expected)
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
            .IsEqualTo("The principal has no key for the encryption type Aes128Sha256");
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
        KerberosKey key = realm.User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;

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
        KerberosKey key = realm.User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;

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
    public async Task OmitsPacForNoAuthDataRequiredService()
    {
        TestRealm realm = new();
        realm.Store.Update(realm.Service, flags: Kerberos.PacUserAccountControl.NoAuthDataRequired);
        KerberosKey key = realm.User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        // MS-KILE 3.3.5.3 the service ticket has no PAC even when the client asks for one, the TGT still has it.
        KrbTgsRep tgsRep = KrbTgsRep.DecodeApplication(realm.Send(NewTgsReq(tgt, tgtPart, s_start,
            paData: [PacRequest(true)])));
        KrbAsRep asRep = KrbAsRep.DecodeApplication(realm.Send(NewAsReq("user", key, s_start,
            sname: Name(ServiceName.Split('/')), paData: [PacRequest(true)])));

        await Assert.That(HasPac(TestKdc.DecryptTicket(tgt.Ticket, realm.Store.Krbtgt))).IsTrue();
        await Assert.That(HasPac(TestKdc.DecryptTicket(tgsRep.Ticket, realm.Service))).IsFalse();
        await Assert.That(HasPac(TestKdc.DecryptTicket(asRep.Ticket, realm.Service))).IsFalse();
    }

    [Test]
    public async Task KeepsPacInTgtWhenKrbtgtIsNoAuthDataRequired()
    {
        TestRealm realm = new();
        realm.Store.Update(realm.Store.Krbtgt, flags: Kerberos.PacUserAccountControl.NoAuthDataRequired);
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();

        // MS-KILE 3.3.5.3 a TGT always has a PAC, so do the service tickets issued from it.
        KrbTgsRep tgsRep = KrbTgsRep.DecodeApplication(realm.Send(NewTgsReq(tgt, tgtPart, s_start)));

        await Assert.That(HasPac(TestKdc.DecryptTicket(tgt.Ticket, realm.Store.Krbtgt))).IsTrue();
        await Assert.That(HasPac(TestKdc.DecryptTicket(tgsRep.Ticket, realm.Service))).IsTrue();
    }

    [Test]
    [Arguments(new[] { EncryptionType.AES256_CTS_HMAC_SHA1_96, EncryptionType.AES128_CTS_HMAC_SHA1_96 }, 0x18u)]
    [Arguments(new[] { EncryptionType.AES128_CTS_HMAC_SHA256_128 }, 0x40u)]
    [Arguments(new[] { EncryptionType.AES256_CTS_HMAC_SHA384_192 }, 0x80u)]
    [Arguments(new[] { EncryptionType.AES256_CTS_HMAC_SHA384_192, EncryptionType.AES256_CTS_HMAC_SHA1_96 }, 0x90u)]
    public async Task EncodesSupportedEncryptionTypesOfService(EncryptionType[] etypes, uint expected)
    {
        TestRealm realm = new();
        realm.Store.Create(["HTTP", "sha"], null, Kerberos.PacUserAccountControl.None,
            [.. etypes.Select(e => (Kerberos.EncryptionType)e)]);
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
        KerberosKey krbtgtKey = realm.Store.Krbtgt.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
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

        ReadOnlyMemory<byte> reply = realm.Processor.Process(request).ReplyBytes;

        await AssertError(reply, KerberosErrorCode.KRB_ERR_GENERIC);
        await Assert.That(KrbError.DecodeApplication(reply).EText).Contains("is not supported");
    }

    [Test]
    public async Task RejectsAsReqWithoutServiceEncryptionType()
    {
        // The client has a key for the requested type for the reply, the service does not for the session key.
        TestRealm realm = new();
        realm.Store.Create(["aes128"], password: null, flags: Kerberos.PacUserAccountControl.None,
            encryptionTypes: [Kerberos.EncryptionType.Aes128Sha1]);
        KerberosKey key = realm.User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
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
            .IsEqualTo("The krbtgt principal has no key for the encryption type Rc4Hmac");
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

    [Test]
    public async Task RecordsAsExchange()
    {
        TestRealm realm = new();
        KerberosKey key = realm.User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
        KrbAsReq request = NewAsReq("user", key, s_start, paData: [PacRequest(true)]);
        request.Body.KdcOptions = KdcOptions.Forwardable | KdcOptions.RenewableOk;
        ReadOnlyMemory<byte> encoded = request.EncodeApplication();

        KdcExchange exchange = realm.Processor.Process(encoded);

        await Assert.That(exchange.RequestType).IsEqualTo(Kerberos.MessageType.AsReq);
        await Assert.That(exchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.None);
        await Assert.That(exchange.ErrorText).IsNull();
        await Assert.That(exchange.Exception).IsNull();
        await Assert.That(exchange.Error).IsNull();
        await Assert.That(exchange.ClientName).IsEqualTo($"user@{Realm}");
        await Assert.That(exchange.ServiceName).IsEqualTo($"krbtgt/{Realm}@{Realm}");
        await Assert.That(exchange.RequestBytes.ToArray()).IsEquivalentTo(encoded.ToArray());
        // The reply is the AS-REP, application tag 11.
        await Assert.That(exchange.ReplyBytes.Span[0]).IsEqualTo((byte)0x6B);

        // The decoded request and the decrypted timestamp are kept for the event.
        await Assert.That(exchange.Request).IsTypeOf<KrbAsReq>();
        await Assert.That(exchange.Timestamp!.PaTimestamp).IsEqualTo(s_start);
        await Assert.That(exchange.Reply).IsTypeOf<KrbAsRep>();
        await Assert.That(exchange.IssuedTicketPart!.Flags)
            .IsEqualTo(TicketFlags.Initial | TicketFlags.PreAuthenticated | TicketFlags.Forwardable);
        await Assert.That(exchange.ReplyPart!.Nonce).IsEqualTo(1234);
        await Assert.That(exchange.ReplyPart.EndTime).IsEqualTo(s_start.AddHours(1));

        // The client key the reply is encrypted with and the krbtgt key the ticket is encrypted with.
        await Assert.That(exchange.Keys.Select(k => k.FullName))
            .IsEquivalentTo([$"user@{Realm}", $"krbtgt/{Realm}@{Realm}"]);
        await Assert.That(exchange.Keys[0].Key).IsEquivalentTo(key.GetKey().ToArray());
        await Assert.That(exchange.Keys[0].Kvno).IsEqualTo(realm.User.Kvno);
        await Assert.That(exchange.Keys[0].EncryptionType).IsEqualTo(Kerberos.EncryptionType.Aes256Sha1);
        KerberosKey krbtgtKey = realm.Store.Krbtgt.State.Keys[0];
        await Assert.That(exchange.Keys[1].Key).IsEquivalentTo(krbtgtKey.GetKey().ToArray());
        await Assert.That((int)exchange.Keys[1].EncryptionType).IsEqualTo((int)krbtgtKey.EncryptionType);
    }

    [Test]
    public async Task BuildsAsRequestAndReplyModel()
    {
        TestRealm realm = new();
        KerberosKey key = realm.User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
        KrbAsReq request = NewAsReq("user", key, s_start, paData: [PacRequest(true)]);
        request.Body.KdcOptions = KdcOptions.Forwardable;
        KdcExchange exchange = realm.Processor.Process(request.EncodeApplication());

        Kerberos.Message requestModel = KdcMessageBuilder.BuildRequest(exchange);
        Kerberos.Message replyModel = KdcMessageBuilder.BuildReply(exchange);

        Kerberos.KdcRequest kdcRequest = (Kerberos.KdcRequest)requestModel;
        await Assert.That(kdcRequest).IsNotTypeOf<Kerberos.TgsRequest>();
        await Assert.That(kdcRequest.MessageType).IsEqualTo(Kerberos.MessageType.AsReq);
        await Assert.That(kdcRequest.ProtocolVersion).IsEqualTo(5);
        await Assert.That(kdcRequest.Body.KdcOption).IsEqualTo(Kerberos.KdcOption.Forwardable);
        await Assert.That(kdcRequest.Body.ClientName!.FullName).IsEqualTo($"user@{Realm}");
        await Assert.That(kdcRequest.Body.ClientName.NameType).IsEqualTo(Kerberos.PrincipalNameType.Principal);
        await Assert.That(kdcRequest.Body.ServiceName!.FullName).IsEqualTo($"krbtgt/{Realm}@{Realm}");
        await Assert.That(kdcRequest.Body.Realm).IsEqualTo(Realm);
        await Assert.That(kdcRequest.Body.Nonce).IsEqualTo(1234);
        await Assert.That(kdcRequest.Body.EncryptionType)
            .IsEquivalentTo([Kerberos.EncryptionType.Aes256Sha1, Kerberos.EncryptionType.Aes128Sha1]);
        await Assert.That(kdcRequest.Body.Till).IsEqualTo(s_start.AddHours(1).LocalDateTime);
        await Assert.That(kdcRequest.PreAuthData).Count().IsEqualTo(2);
        Kerberos.TimestampPreAuthData timestamp = (Kerberos.TimestampPreAuthData)kdcRequest.PreAuthData[0];
        await Assert.That(timestamp.Type).IsEqualTo(Kerberos.PreAuthDataType.EncTimestamp);
        await Assert.That(timestamp.EncryptedData.EncryptionType).IsEqualTo(Kerberos.EncryptionType.Aes256Sha1);
        await Assert.That(timestamp.Timestamp).IsEqualTo(s_start.LocalDateTime);
        Kerberos.PacRequestPreAuthData pacRequest = (Kerberos.PacRequestPreAuthData)kdcRequest.PreAuthData[1];
        await Assert.That(pacRequest.IncludePac).IsTrue();

        Kerberos.KdcReply reply = (Kerberos.KdcReply)replyModel;
        await Assert.That(reply.MessageType).IsEqualTo(Kerberos.MessageType.AsRep);
        await Assert.That(reply.Bytes).IsEquivalentTo(exchange.ReplyBytes.ToArray());
        await Assert.That(reply.ClientName.FullName).IsEqualTo($"user@{Realm}");
        // The salt of the client's key is sent back in ETYPE-INFO2.
        Kerberos.ETypeInfo2PreAuthData etypeInfo = (Kerberos.ETypeInfo2PreAuthData)reply.PreAuthData.Single();
        await Assert.That(etypeInfo.Entry.Single().EncryptionType).IsEqualTo(Kerberos.EncryptionType.Aes256Sha1);
        await Assert.That(etypeInfo.Entry.Single().Salt).IsEqualTo($"{Realm}user");

        await Assert.That(reply.Ticket.ServiceName.FullName).IsEqualTo($"krbtgt/{Realm}@{Realm}");
        await Assert.That(reply.Ticket.EncryptedPart.EncryptionType).IsEqualTo(Kerberos.EncryptionType.Aes256Sha1);
        await Assert.That(reply.Ticket.EncryptedPart.KeyVersion).IsEqualTo(realm.Store.Krbtgt.Kvno);
        Kerberos.TicketPart ticket = reply.Ticket.DecryptedPart!;
        await Assert.That(ticket.Flag).IsEqualTo(
            Kerberos.TicketFlag.Initial | Kerberos.TicketFlag.PreAuthenticated | Kerberos.TicketFlag.Forwardable);
        await Assert.That(ticket.ClientName.FullName).IsEqualTo($"user@{Realm}");
        await Assert.That(ticket.Key.EncryptionType).IsEqualTo(Kerberos.EncryptionType.Aes256Sha1);
        await Assert.That(ticket.Key.Value).Count().IsEqualTo(32);
        await Assert.That(ticket.AuthTime).IsEqualTo(s_start.LocalDateTime);
        await Assert.That(ticket.EndTime).IsEqualTo(s_start.AddHours(1).LocalDateTime);
        await Assert.That(ticket.RenewTill).IsNull();
        await Assert.That(ticket.Pac).IsNotNull();
        await Assert.That(ticket.AuthorizationData.Single()).IsTypeOf<Kerberos.IfRelevantAuthorizationData>();

        Kerberos.KdcReplyPart part = reply.DecryptedPart!;
        await Assert.That(part.Key.Value).IsEquivalentTo(ticket.Key.Value);
        await Assert.That(part.Nonce).IsEqualTo(1234);
        await Assert.That(part.Flag).IsEqualTo(ticket.Flag);
        await Assert.That(part.ServiceName.FullName).IsEqualTo($"krbtgt/{Realm}@{Realm}");
        await Assert.That(part.EncryptedPreAuthData.Single().Type)
            .IsEqualTo(Kerberos.PreAuthDataType.SupportedEncryptionTypes);
    }

    [Test]
    public async Task BuildsPacModel()
    {
        TestRealm realm = new();
        KerberosKey key = realm.User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
        KdcExchange exchange = realm.Processor.Process(NewAsReq("user", key, s_start).EncodeApplication());

        Kerberos.KdcReply reply = (Kerberos.KdcReply)KdcMessageBuilder.BuildReply(exchange);

        Kerberos.Pac pac = reply.Ticket.DecryptedPart!.Pac!;
        await Assert.That(pac.Version).IsEqualTo(0);
        await Assert.That(pac.Buffer.Select(b => b.Type)).Contains(Kerberos.PacBufferType.LogonInfo);
        await Assert.That(pac.Buffer.Select(b => b.Type)).Contains(Kerberos.PacBufferType.ServerChecksum);
        await Assert.That(pac.Buffer.Select(b => b.Type)).Contains(Kerberos.PacBufferType.KdcChecksum);
        await Assert.That(pac.Buffer.All(b => b.Data.Length > 0)).IsTrue();

        Kerberos.PacLogonInfo logon = pac.LogonInfo!;
        await Assert.That(logon.UserName).IsEqualTo("user");
        await Assert.That(logon.DomainName).IsEqualTo("EXAMPLE");
        await Assert.That(logon.DomainSid).IsEqualTo(realm.Store.DomainSid.ToString());
        await Assert.That(logon.UserId).IsEqualTo(realm.User.Rid);
        await Assert.That(logon.UserSid).IsEqualTo(realm.User.Sid);
        await Assert.That(logon.PrimaryGroupId).IsEqualTo(PrincipalStore.DomainUsersRid);
        await Assert.That(logon.GroupId.Single().RelativeId).IsEqualTo(PrincipalStore.DomainUsersRid);
        await Assert.That(logon.GroupId.Single().Attribute).IsEqualTo(Kerberos.PacGroupAttribute.Mandatory
            | Kerberos.PacGroupAttribute.EnabledByDefault | Kerberos.PacGroupAttribute.Enabled);
        await Assert.That(logon.UserAccountControl).IsEqualTo(Kerberos.PacUserAccountControl.NormalAccount);
        await Assert.That(logon.LogonTime).IsEqualTo(s_start.LocalDateTime);
        await Assert.That(logon.LogoffTime).IsNull();
        await Assert.That(logon.ExtraSid).IsEmpty();
    }

    [Test]
    public async Task BuildsTgsRequestModel()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        KrbTgsReq request = NewTgsReq(tgt, tgtPart, s_start);
        KdcExchange exchange = realm.Processor.Process(request.EncodeApplication());

        await Assert.That(exchange.RequestType).IsEqualTo(Kerberos.MessageType.TgsReq);
        await Assert.That(exchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.None);
        // The client is taken from the TGT, a TGS-REQ body has no cname.
        await Assert.That(exchange.ClientName).IsEqualTo($"user@{Realm}");
        await Assert.That(exchange.ServiceName).IsEqualTo($"{ServiceName}@{Realm}");
        await Assert.That(exchange.Tgt).IsNotNull();
        await Assert.That(exchange.Authenticator).IsNotNull();
        // The krbtgt key that decrypts the TGT and the service key the ticket is encrypted with.
        await Assert.That(exchange.Keys.Select(k => k.FullName))
            .IsEquivalentTo([$"krbtgt/{Realm}@{Realm}", $"{ServiceName}@{Realm}"]);

        Kerberos.TgsRequest tgsRequest = (Kerberos.TgsRequest)KdcMessageBuilder.BuildRequest(exchange);
        await Assert.That(tgsRequest.Body.ClientName).IsNull();
        await Assert.That(tgsRequest.Body.ServiceName!.FullName).IsEqualTo($"{ServiceName}@{Realm}");
        Kerberos.ApRequest apRequest = tgsRequest.ApRequest!;
        await Assert.That(tgsRequest.PreAuthData.Single()).IsTypeOf<Kerberos.TgsRequestPreAuthData>();
        await Assert.That(((Kerberos.TgsRequestPreAuthData)tgsRequest.PreAuthData[0]).ApRequest)
            .IsSameReferenceAs(apRequest);
        await Assert.That(apRequest.MessageType).IsEqualTo(Kerberos.MessageType.ApReq);
        await Assert.That(apRequest.Ticket.ServiceName.FullName).IsEqualTo($"krbtgt/{Realm}@{Realm}");
        await Assert.That(apRequest.Ticket.DecryptedPart!.ClientName.FullName).IsEqualTo($"user@{Realm}");
        await Assert.That(apRequest.Ticket.DecryptedPart.Key.Value).IsEquivalentTo(tgtPart.Key.KeyValue.ToArray());
        await Assert.That(apRequest.Authenticator!.ClientName.FullName).IsEqualTo($"user@{Realm}");
        await Assert.That(apRequest.Authenticator.Time).IsEqualTo(s_start.LocalDateTime);
        await Assert.That(apRequest.Authenticator.Checksum!.ChecksumType)
            .IsEqualTo(Kerberos.ChecksumType.HmacSha1Aes256);
        await Assert.That(apRequest.Authenticator.Subkey).IsNull();

        Kerberos.KdcReply reply = (Kerberos.KdcReply)KdcMessageBuilder.BuildReply(exchange);
        await Assert.That(reply.MessageType).IsEqualTo(Kerberos.MessageType.TgsRep);
        await Assert.That(reply.Ticket.ServiceName.FullName).IsEqualTo($"{ServiceName}@{Realm}");
        await Assert.That(reply.Ticket.DecryptedPart!.Flag).IsEqualTo(Kerberos.TicketFlag.PreAuthenticated);
        await Assert.That(reply.Ticket.DecryptedPart.Pac).IsNotNull();
    }

    [Test]
    public async Task RecordsRejectedRequest()
    {
        TestRealm realm = new();

        KdcExchange exchange = realm.Processor.Process(NewAsReq("user", null, s_start).EncodeApplication());

        await Assert.That(exchange.RequestType).IsEqualTo(Kerberos.MessageType.AsReq);
        await Assert.That(exchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.PreAuthRequired);
        await Assert.That(exchange.ErrorText).IsNull();
        await Assert.That(exchange.Exception).IsNull();
        // What the client asked for is recorded even though the request was rejected.
        await Assert.That(exchange.Request).IsNotNull();
        await Assert.That(exchange.ClientName).IsEqualTo($"user@{Realm}");
        await Assert.That(exchange.ServiceName).IsEqualTo($"krbtgt/{Realm}@{Realm}");
        await Assert.That(exchange.Reply).IsNull();
        await Assert.That(exchange.Keys).IsEmpty();
        await AssertError(exchange.ReplyBytes, KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED);

        Kerberos.ErrorReply error = (Kerberos.ErrorReply)KdcMessageBuilder.BuildReply(exchange);
        await Assert.That(error.ErrorCode).IsEqualTo(Kerberos.ErrorCode.PreAuthRequired);
        await Assert.That(error.ErrorText).IsNull();
        await Assert.That(error.ServiceName.FullName).IsEqualTo($"krbtgt/{Realm}@{Realm}");
        await Assert.That(error.ErrorData).IsNotNull();
        // The e-data is METHOD-DATA saying the KDC wants a timestamp and which keys it accepts.
        await Assert.That(error.MethodData!.Select(p => p.Type))
            .IsEquivalentTo([Kerberos.PreAuthDataType.EncTimestamp, Kerberos.PreAuthDataType.ETypeInfo2]);
        Kerberos.ETypeInfo2PreAuthData etypeInfo = (Kerberos.ETypeInfo2PreAuthData)error.MethodData![1];
        await Assert.That(etypeInfo.Entry.Select(e => e.EncryptionType))
            .IsEquivalentTo([Kerberos.EncryptionType.Aes256Sha1, Kerberos.EncryptionType.Aes128Sha1]);

        Kerberos.KdcRequest request = (Kerberos.KdcRequest)KdcMessageBuilder.BuildRequest(exchange);
        await Assert.That(request.Body.EncryptionType)
            .IsEquivalentTo([Kerberos.EncryptionType.Aes256Sha1, Kerberos.EncryptionType.Aes128Sha1]);
        await Assert.That(request.PreAuthData).IsEmpty();
    }

    [Test]
    public async Task RecordsRejectedRequestWithText()
    {
        TestRealm realm = new();
        KrbAsReq request = NewAsReq("user", null, s_start);
        request.Body.Realm = "OTHER.TEST";

        KdcExchange exchange = realm.Processor.Process(request.EncodeApplication());

        await Assert.That(exchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.WrongRealm);
        await Assert.That(exchange.ErrorText).IsEqualTo("The KDC does not serve the realm 'OTHER.TEST'");
        await Assert.That(exchange.ClientName).IsEqualTo("user@OTHER.TEST");
        await Assert.That(exchange.ServiceName).IsEqualTo($"krbtgt/{Realm}@OTHER.TEST");

        Kerberos.ErrorReply error = (Kerberos.ErrorReply)KdcMessageBuilder.BuildReply(exchange);
        await Assert.That(error.ErrorText).IsEqualTo("The KDC does not serve the realm 'OTHER.TEST'");
        await Assert.That(error.MethodData).IsNull();
        await Assert.That(error.ToString())
            .IsEqualTo("WrongRealm: The KDC does not serve the realm 'OTHER.TEST'");
    }

    [Test]
    public async Task RecordsUndecodableRequest()
    {
        TestRealm realm = new();
        // An AS-REQ application tag around a NULL rather than the KDC-REQ sequence.
        byte[] request = [0x6A, 0x02, 0x05, 0x00];

        KdcExchange exchange = realm.Processor.Process(request);

        await Assert.That(exchange.RequestType).IsEqualTo(Kerberos.MessageType.AsReq);
        await Assert.That(exchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.Generic);
        await Assert.That(exchange.ErrorText).StartsWith("Failed to process request: ");
        await Assert.That(exchange.Exception).IsNotNull();
        await Assert.That(exchange.Request).IsNull();
        await Assert.That(exchange.ClientName).IsNull();
        await Assert.That(exchange.ServiceName).IsNull();
        await Assert.That(exchange.RequestBytes.ToArray()).IsEquivalentTo(request);
        await AssertError(exchange.ReplyBytes, KerberosErrorCode.KRB_ERR_GENERIC);

        // The request is a plain message with the claimed type and its bytes.
        Kerberos.Message model = KdcMessageBuilder.BuildRequest(exchange);
        await Assert.That(model).IsNotTypeOf<Kerberos.KdcRequest>();
        await Assert.That(model.MessageType).IsEqualTo(Kerberos.MessageType.AsReq);
        await Assert.That(model.Bytes).IsEquivalentTo(request);
    }

    [Test]
    public async Task RecordsUnsupportedMessageType()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, _) = realm.GetTgt();
        KrbApReq apReq = new()
        {
            Ticket = tgt.Ticket,
            Authenticator = tgt.EncryptedPart,
        };

        KdcExchange exchange = realm.Processor.Process(apReq.EncodeApplication());

        await Assert.That(exchange.RequestType).IsEqualTo(Kerberos.MessageType.Unknown);
        await Assert.That(exchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.Generic);
        // The KDC rejected the message on purpose, there was no unexpected exception.
        await Assert.That(exchange.Exception).IsNull();
        await Assert.That(exchange.ErrorText).Contains("is not supported");
    }

    [Test]
    public async Task ReplacesReplyOfExchange()
    {
        TestRealm realm = new();
        KerberosKey key = realm.User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
        KdcExchange exchange = realm.Processor.Process(NewAsReq("user", key, s_start).EncodeApplication());

        realm.Processor.ReplaceResponseTooBig(exchange, "too big");

        await Assert.That(exchange.RequestType).IsEqualTo(Kerberos.MessageType.AsReq);
        await Assert.That(exchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.ResponseTooBig);
        await Assert.That(exchange.ErrorText).IsEqualTo("too big");
        // The request details and keys stay, the ticket was not sent so it goes.
        await Assert.That(exchange.Request).IsNotNull();
        await Assert.That(exchange.ClientName).IsEqualTo($"user@{Realm}");
        await Assert.That(exchange.Keys).Count().IsEqualTo(2);
        await Assert.That(exchange.Reply).IsNull();
        await Assert.That(exchange.IssuedTicketPart).IsNull();
        await Assert.That(exchange.ReplyPart).IsNull();
        await AssertError(exchange.ReplyBytes, KerberosErrorCode.KRB_ERR_RESPONSE_TOO_BIG);
        await Assert.That(KdcMessageBuilder.BuildReply(exchange)).IsTypeOf<Kerberos.ErrorReply>();
    }

    [Test]
    public async Task BuildsAddressesAndAdditionalTickets()
    {
        TestRealm realm = new();
        KerberosKey key = realm.User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
        KrbAsReq asReq = NewAsReq("user", key, s_start);
        asReq.Body.Addresses =
        [
            new KrbHostAddress { AddressType = AddressType.IPv4, Address = new byte[] { 192, 0, 2, 1 } },
            new KrbHostAddress { AddressType = AddressType.IPv6, Address = IPAddress.IPv6Loopback.GetAddressBytes() },
            new KrbHostAddress { AddressType = AddressType.NetBios, Address = Encoding.ASCII.GetBytes("HOST    ") },
            // An IPv4 address of the wrong length and a type without a known format are shown as hex.
            new KrbHostAddress { AddressType = AddressType.IPv4, Address = new byte[] { 1, 2, 3 } },
            new KrbHostAddress { AddressType = (AddressType)3, Address = new byte[] { 0xAB, 0xCD } },
        ];
        string[] expected = ["192.0.2.1", "::1", "HOST", "IPv4 010203", "Directional ABCD"];

        KdcExchange asExchange = realm.Processor.Process(asReq.EncodeApplication());

        await Assert.That(asExchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.None);
        Kerberos.KdcRequest request = (Kerberos.KdcRequest)KdcMessageBuilder.BuildRequest(asExchange);
        await Assert.That(request.Body.Address.Select(a => a.ToString())).IsEquivalentTo(expected);
        await Assert.That(request.Body.Address[0].AddressType).IsEqualTo(Kerberos.AddressType.IPv4);
        await Assert.That(request.Body.Address[0].Address).IsEquivalentTo(new byte[] { 192, 0, 2, 1 });
        await Assert.That(request.Body.Address[2].Address).IsEquivalentTo(Encoding.ASCII.GetBytes("HOST    "));
        await Assert.That(request.Body.AdditionalTicket).IsEmpty();
        // The ticket is restricted to the addresses of the request, listed in the ticket and the reply part.
        Kerberos.KdcReply reply = (Kerberos.KdcReply)KdcMessageBuilder.BuildReply(asExchange);
        await Assert.That(reply.Ticket.DecryptedPart!.Address.Select(a => a.ToString())).IsEquivalentTo(expected);
        await Assert.That(reply.DecryptedPart!.Address.Select(a => a.ToString())).IsEquivalentTo(expected);

        // A user to user request carries the TGT of the service as an additional ticket.
        KrbAsRep tgt = KrbAsRep.DecodeApplication(asExchange.ReplyBytes);
        KrbEncAsRepPart tgtPart = DecryptAsRep(tgt, key);
        KrbTgsReq tgsReq = NewTgsReq(tgt, tgtPart, s_start, service: "user", configureBody: b =>
        {
            b.KdcOptions |= KdcOptions.EncTktInSkey;
            b.AdditionalTickets = [tgt.Ticket];
        });

        KdcExchange tgsExchange = realm.Processor.Process(tgsReq.EncodeApplication());

        await Assert.That(tgsExchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.None);
        Kerberos.TgsRequest tgsRequest = (Kerberos.TgsRequest)KdcMessageBuilder.BuildRequest(tgsExchange);
        await Assert.That(tgsRequest.Body.KdcOption).IsEqualTo(Kerberos.KdcOption.EncTktInSkey);
        Kerberos.Ticket additional = tgsRequest.Body.AdditionalTicket.Single();
        await Assert.That(additional.ServiceName.FullName).IsEqualTo($"krbtgt/{Realm}@{Realm}");
        await Assert.That(additional.EncryptedPart.Cipher).IsEquivalentTo(tgt.Ticket.EncryptedPart.Cipher.ToArray());
        // Only the TGT of the AP-REQ is decrypted, the additional ticket is shown as sent.
        await Assert.That(additional.DecryptedPart).IsNull();
        await Assert.That(tgsRequest.ApRequest!.Ticket.DecryptedPart!.Address.Select(a => a.ToString()))
            .IsEquivalentTo(expected);
    }

    [Test]
    public async Task BuildsAuthorizationDataThatIsNotAPac()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        // A TGT from a KDC that puts other things in the authorization data: an AD-IF-RELEVANT without a PAC, a type
        // the model does not decode and an AD-IF-RELEVANT that is not a sequence.
        KrbTicket forged = ForgeTgt(realm, tgt, part => part.AuthorizationData =
        [
            new KrbAuthorizationData
            {
                Type = AuthorizationDataType.AdIfRelevant,
                Data = new KrbAuthorizationDataSequence
                {
                    AuthorizationData =
                    [
                        new KrbAuthorizationData
                        {
                            // AD-KDC-ISSUED, which Kerberos.NET has no name for.
                            Type = (AuthorizationDataType)4,
                            Data = new byte[] { 9, 9 },
                        },
                    ],
                }.Encode(),
            },
            new KrbAuthorizationData { Type = AuthorizationDataType.AdAndOr, Data = new byte[] { 1 } },
            new KrbAuthorizationData { Type = AuthorizationDataType.AdIfRelevant, Data = new byte[] { 0xFF } },
        ]);

        KdcExchange exchange = realm.Processor.Process(
            NewTgsReq(tgt, tgtPart, s_start, ticket: forged).EncodeApplication());

        await Assert.That(exchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.None);
        Kerberos.TgsRequest request = (Kerberos.TgsRequest)KdcMessageBuilder.BuildRequest(exchange);
        Kerberos.TicketPart ticket = request.ApRequest!.Ticket.DecryptedPart!;
        await Assert.That(ticket.Pac).IsNull();
        await Assert.That(ticket.AuthorizationData).Count().IsEqualTo(3);

        Kerberos.IfRelevantAuthorizationData ifRelevant =
            (Kerberos.IfRelevantAuthorizationData)ticket.AuthorizationData[0];
        await Assert.That(ifRelevant.Type).IsEqualTo(Kerberos.AuthorizationDataType.IfRelevant);
        Kerberos.AuthorizationData kdcIssued = ifRelevant.Element.Single();
        await Assert.That(kdcIssued.GetType()).IsEqualTo(typeof(Kerberos.AuthorizationData));
        await Assert.That(kdcIssued.Type).IsEqualTo(Kerberos.AuthorizationDataType.KdcIssued);
        await Assert.That(kdcIssued.Data).IsEquivalentTo(new byte[] { 9, 9 });
        await Assert.That(kdcIssued.ToString()).IsEqualTo("KdcIssued, 2 bytes");
        await Assert.That(ifRelevant.ToString()).IsEqualTo("IfRelevant [KdcIssued, 2 bytes]");

        Kerberos.AuthorizationData andOr = ticket.AuthorizationData[1];
        await Assert.That(andOr.GetType()).IsEqualTo(typeof(Kerberos.AuthorizationData));
        await Assert.That(andOr.Type).IsEqualTo(Kerberos.AuthorizationDataType.AndOr);
        await Assert.That(andOr.ToString()).IsEqualTo("AndOr, 1 bytes");

        // The AD-IF-RELEVANT that did not decode is listed with its type and bytes.
        Kerberos.AuthorizationData undecodable = ticket.AuthorizationData[2];
        await Assert.That(undecodable.GetType()).IsEqualTo(typeof(Kerberos.AuthorizationData));
        await Assert.That(undecodable.Type).IsEqualTo(Kerberos.AuthorizationDataType.IfRelevant);
        await Assert.That(undecodable.Data).IsEquivalentTo(new byte[] { 0xFF });
    }

    [Test]
    public async Task BuildsPacThatDoesNotDecode()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        // A PACTYPE header with no buffers, one too short to be a header, and one claiming two buffers with only the
        // first PAC_INFO_BUFFER present and pointing past the end of the data.
        byte[] empty = new byte[8];
        byte[] tooShort = [1, 2, 3];
        byte[] truncated =
        [
            2, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 4, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0,
        ];
        KrbAuthorizationData[] authorizationData =
        [
            new KrbAuthorizationData
            {
                Type = AuthorizationDataType.AdIfRelevant,
                Data = new KrbAuthorizationDataSequence
                {
                    AuthorizationData =
                    [
                        new KrbAuthorizationData { Type = AuthorizationDataType.AdWin2kPac, Data = empty },
                        new KrbAuthorizationData { Type = AuthorizationDataType.AdWin2kPac, Data = tooShort },
                        new KrbAuthorizationData { Type = AuthorizationDataType.AdWin2kPac, Data = truncated },
                    ],
                }.Encode(),
            },
        ];

        KdcExchange exchange = realm.Processor.Process(NewTgsReq(tgt, tgtPart, s_start,
            configureAuthenticator: a => a.AuthorizationData = authorizationData).EncodeApplication());

        await Assert.That(exchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.None);
        Kerberos.TgsRequest request = (Kerberos.TgsRequest)KdcMessageBuilder.BuildRequest(exchange);
        Kerberos.IfRelevantAuthorizationData ifRelevant =
            (Kerberos.IfRelevantAuthorizationData)request.ApRequest!.Authenticator!.AuthorizationData.Single();
        Kerberos.Pac[] pacs = [.. ifRelevant.Element.Select(e => ((Kerberos.PacAuthorizationData)e).Pac)];
        await Assert.That(pacs).Count().IsEqualTo(3);
        await Assert.That(pacs.Select(p => p.LogonInfo)).All().Satisfy(l => l.IsNull());
        await Assert.That(pacs.Select(p => p.ClientInfo)).All().Satisfy(c => c.IsNull());
        await Assert.That(pacs.Select(p => p.UpnDnsInfo)).All().Satisfy(u => u.IsNull());

        await Assert.That(pacs[0].Buffer).IsEmpty();
        await Assert.That(pacs[0].ToString()).IsEqualTo("PAC with 0 buffers");
        await Assert.That(pacs[1].Buffer).IsEmpty();
        await Assert.That(pacs[1].Version).IsEqualTo(0);
        // The first buffer is listed without data as it is out of bounds, the second header is missing.
        Kerberos.PacBuffer buffer = pacs[2].Buffer.Single();
        await Assert.That(buffer.Type).IsEqualTo(Kerberos.PacBufferType.LogonInfo);
        await Assert.That(buffer.Data).IsEmpty();
        await Assert.That(buffer.ToString()).IsEqualTo("LogonInfo, 0 bytes");
        await Assert.That(pacs[2].ToString()).IsEqualTo("PAC with 1 buffers");
        await Assert.That(ifRelevant.Element[2].ToString()).IsEqualTo("Win2kPac PAC with 1 buffers");
    }

    [Test]
    public async Task BuildsPacWithExtraSidsAndUpn()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        SecurityIdentifier domainSid = realm.Store.DomainSid;
        SecurityIdentifier administrators = new(IdentifierAuthority.NTAuthority, [32, 544], 0);
        SecurityIdentifier resourceDomain = new(IdentifierAuthority.NTAuthority, [21, 1, 2, 3], 0);
        // A PAC like Windows issues with the buffers Obol does not create itself.
        PrivilegedAttributeCertificate pac = new()
        {
            LogonInfo = new PacLogonInfo
            {
                DomainName = "EXAMPLE",
                UserName = "user",
                UserDisplayName = "A User",
                DomainSid = domainSid,
                UserSid = new SecurityIdentifier(domainSid, 1105),
                GroupSid = new SecurityIdentifier(domainSid, 513),
                GroupIds = [new GroupMembership { RelativeId = 513, Attributes = SidAttributes.SE_GROUP_ENABLED }],
                LogonTime = s_start,
                PwdLastChangeTime = s_start.AddDays(-1),
                KickOffTime = new RpcFileTime { LowDateTime = 0xFFFFFFFF, HighDateTime = 0x7FFFFFFF },
                UserFlags = UserFlags.LOGON_EXTRA_SIDS | UserFlags.LOGON_RESOURCE_GROUPS,
                ExtraIds =
                [
                    new RpcSidAttributes
                    {
                        Sid = administrators.ToRpcSid(),
                        Attributes = SidAttributes.SE_GROUP_MANDATORY | SidAttributes.SE_GROUP_ENABLED,
                    },
                ],
                ResourceDomainId = resourceDomain.ToRpcSid(),
                ResourceGroupIds =
                [
                    new GroupMembership
                    {
                        RelativeId = 1234,
                        Attributes = SidAttributes.SE_GROUP_RESOURCE | SidAttributes.SE_GROUP_ENABLED,
                    },
                ],
            },
            ClientInformation = new PacClientInfo
            {
                ClientId = RpcFileTime.ConvertWithoutMicroseconds(s_start),
                Name = "user",
            },
            UpnDomainInformation = new UpnDomainInfo
            {
                Upn = "user@example.test",
                Domain = "EXAMPLE.TEST",
                Flags = UpnDomainFlags.U,
            },
        };
        KerberosKey kdcKey = realm.Store.Krbtgt.State.Keys[0];
        KrbAuthorizationData[] authorizationData =
        [
            new KrbAuthorizationData
            {
                Type = AuthorizationDataType.AdIfRelevant,
                Data = new KrbAuthorizationDataSequence
                {
                    AuthorizationData =
                    [
                        new KrbAuthorizationData
                        {
                            Type = AuthorizationDataType.AdWin2kPac,
                            Data = pac.Encode(kdcKey, realm.User.State.Keys[0]),
                        },
                    ],
                }.Encode(),
            },
        ];

        KdcExchange exchange = realm.Processor.Process(NewTgsReq(tgt, tgtPart, s_start,
            configureAuthenticator: a => a.AuthorizationData = authorizationData).EncodeApplication());

        await Assert.That(exchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.None);
        Kerberos.TgsRequest request = (Kerberos.TgsRequest)KdcMessageBuilder.BuildRequest(exchange);
        Kerberos.IfRelevantAuthorizationData ifRelevant =
            (Kerberos.IfRelevantAuthorizationData)request.ApRequest!.Authenticator!.AuthorizationData.Single();
        Kerberos.Pac actual = ((Kerberos.PacAuthorizationData)ifRelevant.Element.Single()).Pac;
        await Assert.That(actual.Buffer.Select(b => b.Type)).IsEquivalentTo(
        [
            Kerberos.PacBufferType.LogonInfo,
            Kerberos.PacBufferType.ClientInfo,
            Kerberos.PacBufferType.UpnDnsInfo,
            Kerberos.PacBufferType.ServerChecksum,
            Kerberos.PacBufferType.KdcChecksum,
        ]);

        Kerberos.PacLogonInfo logon = actual.LogonInfo!;
        await Assert.That(logon.UserDisplayName).IsEqualTo("A User");
        await Assert.That(logon.UserSid).IsEqualTo($"{domainSid}-1105");
        await Assert.That(logon.PrimaryGroupSid).IsEqualTo($"{domainSid}-513");
        await Assert.That(logon.LogonTime).IsEqualTo(s_start.LocalDateTime);
        await Assert.That(logon.PasswordLastSet).IsEqualTo(s_start.AddDays(-1).LocalDateTime);
        await Assert.That(logon.KickOffTime).IsNull();
        await Assert.That(logon.PasswordMustChange).IsNull();
        await Assert.That(logon.UserFlag)
            .IsEqualTo(Kerberos.PacUserFlag.ExtraSids | Kerberos.PacUserFlag.ResourceGroups);
        Kerberos.PacSidAttributes extra = logon.ExtraSid.Single();
        await Assert.That(extra.Sid).IsEqualTo("S-1-5-32-544");
        await Assert.That(extra.Attribute)
            .IsEqualTo(Kerberos.PacGroupAttribute.Mandatory | Kerberos.PacGroupAttribute.Enabled);
        await Assert.That(extra.ToString()).IsEqualTo("S-1-5-32-544 (Mandatory, Enabled)");
        await Assert.That(logon.ResourceDomainSid).IsEqualTo("S-1-5-21-1-2-3");
        Kerberos.PacGroupMembership resourceGroup = logon.ResourceGroupId.Single();
        await Assert.That(resourceGroup.RelativeId).IsEqualTo(1234u);
        await Assert.That(resourceGroup.Attribute)
            .IsEqualTo(Kerberos.PacGroupAttribute.Resource | Kerberos.PacGroupAttribute.Enabled);
        await Assert.That(resourceGroup.ToString()).IsEqualTo("1234 (Enabled, Resource)");

        Kerberos.PacClientInfo client = actual.ClientInfo!;
        await Assert.That(client.Name).IsEqualTo("user");
        await Assert.That(client.ClientId).IsEqualTo(s_start.LocalDateTime);
        await Assert.That(client.ToString()).IsEqualTo($"user at {s_start.LocalDateTime}");

        Kerberos.PacUpnDnsInfo upn = actual.UpnDnsInfo!;
        await Assert.That(upn.Upn).IsEqualTo("user@example.test");
        await Assert.That(upn.DnsDomainName).IsEqualTo("EXAMPLE.TEST");
        await Assert.That(upn.Flag).IsEqualTo(Kerberos.PacUpnDnsFlag.NoUpn);
        await Assert.That(upn.ToString()).IsEqualTo("user@example.test");
    }

    [Test]
    public async Task BuildsErrorWithClientAndErrorDataThatIsNotMethodData()
    {
        // A KRB-ERROR as another KDC might send it, with the client and time of the request and e-data that is not
        // METHOD-DATA, such as the KERB-ERROR-DATA of Windows.
        KrbError error = new()
        {
            ErrorCode = KerberosErrorCode.KDC_ERR_POLICY,
            Realm = Realm,
            SName = Name("krbtgt", Realm),
            CName = Name("user"),
            CRealm = Realm,
            CTime = s_start,
            Cusec = 500,
            STime = s_start.AddSeconds(1),
            Susc = 250,
            EText = "Not allowed",
            EData = new byte[] { 1, 2, 3 },
        };
        KdcExchange exchange = new();
        exchange.SetError(error, error.EncodeApplication());

        Kerberos.ErrorReply reply = (Kerberos.ErrorReply)KdcMessageBuilder.BuildReply(exchange);

        await Assert.That(reply.MessageType).IsEqualTo(Kerberos.MessageType.Error);
        await Assert.That(reply.ErrorCode).IsEqualTo(Kerberos.ErrorCode.Policy);
        await Assert.That(reply.ClientName!.FullName).IsEqualTo($"user@{Realm}");
        await Assert.That(reply.ClientTime).IsEqualTo(s_start.AddTicks(500 * 10).LocalDateTime);
        await Assert.That(reply.ServerTime).IsEqualTo(s_start.AddSeconds(1).AddTicks(250 * 10).LocalDateTime);
        await Assert.That(reply.ServiceName.FullName).IsEqualTo($"krbtgt/{Realm}@{Realm}");
        await Assert.That(reply.ErrorData).IsEquivalentTo(new byte[] { 1, 2, 3 });
        await Assert.That(reply.MethodData).IsNull();
        await Assert.That(reply.ToString()).IsEqualTo("Policy: Not allowed");
        // Nothing was received for the exchange so the request is an empty unknown message.
        Kerberos.Message request = KdcMessageBuilder.BuildRequest(exchange);
        await Assert.That(request.GetType()).IsEqualTo(typeof(Kerberos.Message));
        await Assert.That(request.MessageType).IsEqualTo(Kerberos.MessageType.Unknown);
        await Assert.That(request.Bytes).IsEmpty();
        await Assert.That(request.ToString()).IsEqualTo("Unknown, 0 bytes");
    }

    [Test]
    public async Task BuildsMethodDataWithUnknownTypeAndEntryWithoutSalt()
    {
        KrbError error = new()
        {
            ErrorCode = KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED,
            Realm = Realm,
            SName = Name("krbtgt", Realm),
            EData = new KrbMethodData
            {
                MethodData =
                [
                    new KrbPaData
                    {
                        Type = PaDataType.PA_ETYPE_INFO2,
                        Value = new KrbETypeInfo2
                        {
                            ETypeInfo =
                            [
                                new KrbETypeInfo2Entry { EType = EncryptionType.AES128_CTS_HMAC_SHA1_96 },
                                new KrbETypeInfo2Entry
                                {
                                    EType = EncryptionType.AES256_CTS_HMAC_SHA1_96,
                                    Salt = "salt",
                                    S2kParams = new byte[] { 0, 0, 0x10, 0 },
                                },
                            ],
                        }.Encode(),
                    },
                    new KrbPaData { Type = PaDataType.PA_FX_FAST, Value = new byte[] { 0x30, 0 } },
                    // A PA-ENC-TIMESTAMP that does not decode is listed with its bytes.
                    new KrbPaData { Type = PaDataType.PA_ENC_TIMESTAMP, Value = new byte[] { 0xFF } },
                ],
            }.Encode(),
            STime = s_start,
        };
        KdcExchange exchange = new();
        exchange.SetError(error, error.EncodeApplication());

        Kerberos.ErrorReply reply = (Kerberos.ErrorReply)KdcMessageBuilder.BuildReply(exchange);

        await Assert.That(reply.MethodData!).Count().IsEqualTo(3);
        Kerberos.ETypeInfo2PreAuthData etypeInfo = (Kerberos.ETypeInfo2PreAuthData)reply.MethodData![0];
        await Assert.That(etypeInfo.Entry[0].Salt).IsNull();
        await Assert.That(etypeInfo.Entry[0].StringToKeyParameters).IsNull();
        await Assert.That(etypeInfo.Entry[0].ToString()).IsEqualTo("etype Aes128Sha1");
        await Assert.That(etypeInfo.Entry[1].Salt).IsEqualTo("salt");
        await Assert.That(etypeInfo.Entry[1].StringToKeyParameters).IsEquivalentTo(new byte[] { 0, 0, 0x10, 0 });
        await Assert.That(etypeInfo.Entry[1].ToString()).IsEqualTo("etype Aes256Sha1 salt salt");
        await Assert.That(etypeInfo.ToString()).IsEqualTo("ETypeInfo2 etype Aes128Sha1, etype Aes256Sha1 salt salt");

        Kerberos.PreAuthData fast = reply.MethodData[1];
        await Assert.That(fast.GetType()).IsEqualTo(typeof(Kerberos.PreAuthData));
        await Assert.That(fast.Type).IsEqualTo(Kerberos.PreAuthDataType.FxFast);
        await Assert.That(fast.Value).IsEquivalentTo(new byte[] { 0x30, 0 });
        await Assert.That(fast.ToString()).IsEqualTo("FxFast, 2 bytes");

        Kerberos.PreAuthData timestamp = reply.MethodData[2];
        await Assert.That(timestamp.GetType()).IsEqualTo(typeof(Kerberos.PreAuthData));
        await Assert.That(timestamp.Type).IsEqualTo(Kerberos.PreAuthDataType.EncTimestamp);
        await Assert.That(timestamp.Value).IsEquivalentTo(new byte[] { 0xFF });
    }

    [Test]
    public async Task BuildsUnknownMessagesForExchangeWithoutReply()
    {
        KdcExchange exchange = new() { RequestBytes = new byte[] { 1, 2 } };

        Kerberos.Message request = KdcMessageBuilder.BuildRequest(exchange);
        Kerberos.Message reply = KdcMessageBuilder.BuildReply(exchange);

        await Assert.That(request.GetType()).IsEqualTo(typeof(Kerberos.Message));
        await Assert.That(request.MessageType).IsEqualTo(Kerberos.MessageType.Unknown);
        await Assert.That(request.Bytes).IsEquivalentTo(new byte[] { 1, 2 });
        await Assert.That(request.ToString()).IsEqualTo("Unknown, 2 bytes");
        await Assert.That(reply.GetType()).IsEqualTo(typeof(Kerberos.Message));
        await Assert.That(reply.MessageType).IsEqualTo(Kerberos.MessageType.Unknown);
        await Assert.That(reply.Bytes).IsEmpty();
    }

    [Test]
    public async Task FormatsAsExchangeModel()
    {
        TestRealm realm = new();
        KerberosKey key = realm.User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
        KrbAsReq asReq = NewAsReq("user", key, s_start, paData: [PacRequest(true)]);
        KdcExchange exchange = realm.Processor.Process(asReq.EncodeApplication());
        string krbtgt = $"krbtgt/{Realm}@{Realm}";
        DateTime start = s_start.LocalDateTime;
        DateTime end = s_start.AddHours(1).LocalDateTime;

        Kerberos.KdcRequest request = (Kerberos.KdcRequest)KdcMessageBuilder.BuildRequest(exchange);
        Kerberos.KdcReply reply = (Kerberos.KdcReply)KdcMessageBuilder.BuildReply(exchange);

        await Assert.That(request.ToString()).IsEqualTo($"AsReq user@{Realm} -> {krbtgt}");
        await Assert.That(request.Body.ToString()).IsEqualTo($"user@{Realm} -> {krbtgt}");
        await Assert.That(request.Body.ClientName!.ToString()).IsEqualTo($"user@{Realm}");
        Kerberos.TimestampPreAuthData timestamp = (Kerberos.TimestampPreAuthData)request.PreAuthData[0];
        await Assert.That(timestamp.EncryptedData.KeyVersion).IsEqualTo(realm.User.Kvno);
        await Assert.That(timestamp.EncryptedData.ToString())
            .IsEqualTo($"etype Aes256Sha1 kvno {realm.User.Kvno}, {timestamp.EncryptedData.Cipher.Length} bytes");
        await Assert.That(timestamp.ToString()).IsEqualTo($"EncTimestamp {start} ({timestamp.EncryptedData})");
        await Assert.That(request.PreAuthData[1].ToString()).IsEqualTo("PacRequest True");

        await Assert.That(reply.ToString()).IsEqualTo($"AsRep user@{Realm} -> {krbtgt}");
        await Assert.That(reply.PreAuthData.Single().ToString())
            .IsEqualTo($"ETypeInfo2 etype Aes256Sha1 salt {Realm}user");
        await Assert.That(reply.Ticket.EncryptedPart.ToString()).IsEqualTo(
            $"etype Aes256Sha1 kvno {realm.Store.Krbtgt.Kvno}, {reply.Ticket.EncryptedPart.Cipher.Length} bytes");
        await Assert.That(reply.Ticket.ToString()).IsEqualTo($"{krbtgt} ({reply.Ticket.EncryptedPart})");
        await Assert.That(reply.EncryptedPart.ToString())
            .IsEqualTo($"etype Aes256Sha1 kvno {realm.User.Kvno}, {reply.EncryptedPart.Cipher.Length} bytes");

        Kerberos.TicketPart ticket = reply.Ticket.DecryptedPart!;
        await Assert.That(ticket.ToString()).IsEqualTo($"user@{Realm} PreAuthenticated, Initial, expires {end}");
        await Assert.That(ticket.Key.ToString()).IsEqualTo("etype Aes256Sha1, 32 bytes");
        Kerberos.IfRelevantAuthorizationData ifRelevant =
            (Kerberos.IfRelevantAuthorizationData)ticket.AuthorizationData.Single();
        Kerberos.PacAuthorizationData pacData = (Kerberos.PacAuthorizationData)ifRelevant.Element.Single();
        Kerberos.Pac pac = pacData.Pac;
        await Assert.That(pac.ToString()).IsEqualTo($"PAC for EXAMPLE\\user, {pac.Buffer.Length} buffers");
        await Assert.That(pacData.ToString()).IsEqualTo($"Win2kPac {pac}");
        await Assert.That(ifRelevant.ToString()).IsEqualTo($"IfRelevant [Win2kPac {pac}]");
        Kerberos.PacBuffer logonBuffer = pac.Buffer.First(b => b.Type == Kerberos.PacBufferType.LogonInfo);
        await Assert.That(logonBuffer.ToString()).IsEqualTo($"LogonInfo, {logonBuffer.Data.Length} bytes");
        await Assert.That(pac.LogonInfo!.ToString()).IsEqualTo($"EXAMPLE\\user ({realm.User.Sid})");
        await Assert.That(pac.LogonInfo.GroupId.Single().ToString())
            .IsEqualTo("513 (Mandatory, EnabledByDefault, Enabled)");
        await Assert.That(pac.ClientInfo!.ToString()).IsEqualTo($"user at {start}");

        Kerberos.KdcReplyPart part = reply.DecryptedPart!;
        await Assert.That(part.ToString()).IsEqualTo($"{krbtgt} PreAuthenticated, Initial, expires {end}");
        await Assert.That(part.LastRequest.Single().ToString()).IsEqualTo($"0: {start}");
        Kerberos.PreAuthData supported = part.EncryptedPreAuthData.Single();
        await Assert.That(supported.ToString()).IsEqualTo($"SupportedEncryptionTypes, {supported.Value.Length} bytes");
    }

    [Test]
    public async Task FormatsTgsExchangeModel()
    {
        TestRealm realm = new();
        (KrbAsRep tgt, KrbEncAsRepPart tgtPart) = realm.GetTgt();
        KdcExchange exchange = realm.Processor.Process(NewTgsReq(tgt, tgtPart, s_start).EncodeApplication());
        string service = $"{ServiceName}@{Realm}";
        DateTime start = s_start.LocalDateTime;

        Kerberos.TgsRequest request = (Kerberos.TgsRequest)KdcMessageBuilder.BuildRequest(exchange);
        Kerberos.KdcReply reply = (Kerberos.KdcReply)KdcMessageBuilder.BuildReply(exchange);

        await Assert.That(request.ToString()).IsEqualTo($"TgsReq -> {service}");
        await Assert.That(request.Body.ToString()).IsEqualTo($"-> {service}");
        Kerberos.ApRequest apRequest = request.ApRequest!;
        await Assert.That(apRequest.Ticket.ToString())
            .IsEqualTo($"krbtgt/{Realm}@{Realm} ({apRequest.Ticket.EncryptedPart})");
        await Assert.That(apRequest.ToString()).IsEqualTo($"AP-REQ {apRequest.Ticket}");
        await Assert.That(request.PreAuthData.Single().ToString()).IsEqualTo($"TgsReq {apRequest.Ticket}");
        await Assert.That(apRequest.EncryptedAuthenticator.ToString())
            .IsEqualTo($"etype Aes256Sha1, {apRequest.EncryptedAuthenticator.Cipher.Length} bytes");
        await Assert.That(apRequest.Authenticator!.ToString()).IsEqualTo($"user@{Realm} at {start}");
        await Assert.That(apRequest.Authenticator.Checksum!.ToString()).IsEqualTo("cksumtype HmacSha1Aes256, 12 bytes");

        await Assert.That(reply.ToString()).IsEqualTo($"TgsRep user@{Realm} -> {service}");
        await Assert.That(reply.Ticket.ToString()).IsEqualTo($"{service} ({reply.Ticket.EncryptedPart})");
        await Assert.That(reply.Ticket.DecryptedPart!.ToString())
            .IsEqualTo($"user@{Realm} PreAuthenticated, expires {s_start.AddHours(1).LocalDateTime}");
    }

    [Test]
    public async Task FormatsTimestampTheKdcDidNotDecrypt()
    {
        TestRealm realm = new();
        KerberosKey key = realm.User.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;

        KdcExchange exchange = realm.Processor.Process(NewAsReq("unknown", key, s_start).EncodeApplication());

        await Assert.That(exchange.ErrorCode).IsEqualTo(Kerberos.ErrorCode.ClientPrincipalUnknown);
        Kerberos.KdcRequest request = (Kerberos.KdcRequest)KdcMessageBuilder.BuildRequest(exchange);
        Kerberos.TimestampPreAuthData timestamp = (Kerberos.TimestampPreAuthData)request.PreAuthData.Single();
        await Assert.That(timestamp.Timestamp).IsNull();
        await Assert.That(timestamp.ToString()).IsEqualTo($"EncTimestamp ({timestamp.EncryptedData})");
    }
}
