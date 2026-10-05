using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Obol.Protocol;

namespace Obol.Tests;

/// <summary>Authenticates against the KDC with the Kerberos.NET client.</summary>
public class PrincipalTests
{
    private const string ServiceName = "HTTP/web.example.test";

    [Test]
    public async Task AnswersRequestSentBeforeStart()
    {
        using TestKdc kdc = new(start: false);
        using KerberosClient client = kdc.CreateClient();

        // The request waits in the TCP backlog until the KDC starts, after the principal was added.
        Task authenticate = client.Authenticate(
            new KerberosPasswordCredential("user", TestKdc.Password, TestKdc.Realm));
        await Task.Delay(500);
        await Assert.That(authenticate.IsCompleted).IsFalse();

        kdc.AddUser("user");
        kdc.Start();
        await authenticate;

        await Assert.That(TestKdc.GetTgt(client).Flags.HasFlag(TicketFlags.Initial)).IsTrue();
    }

    [Test]
    public async Task AuthenticatesWithPasswordAndGetsServiceTicket()
    {
        using TestKdc kdc = new();
        ObolPrincipal user = kdc.AddUser("user");
        ObolPrincipal service = kdc.AddService(ServiceName);

        using KerberosClient client = kdc.CreateClient();
        await client.Authenticate(new KerberosPasswordCredential("user", TestKdc.Password, TestKdc.Realm));
        KrbApReq apReq = await client.GetServiceTicket(ServiceName);

        // Decrypting the ticket with the service's key checks it was issued for the service and has the PAC.
        KerberosKey serviceKey = service.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
        KerberosAuthenticator authenticator = new(new KerberosValidator(serviceKey));
        ClaimsIdentity identity = await authenticator.Authenticate(apReq.EncodeGssApi());

        await Assert.That(identity.Name).IsEqualTo($"user@{TestKdc.Realm}");
        await Assert.That(identity.FindFirst(ClaimTypes.Sid)?.Value).IsEqualTo(user.Sid);
        await Assert.That(user.Sid).StartsWith($"{kdc.Store.DomainSid}-");
        await Assert.That(identity.FindAll(ClaimTypes.GroupSid).Select(c => c.Value))
            .Contains($"{kdc.Store.DomainSid}-513");
        await Assert.That(kdc.Fault).IsNull();
    }

    [Test]
    public async Task AuthenticatesOverUdp()
    {
        using TestKdc kdc = new(transport: ObolKdcTransport.Udp);
        kdc.AddUser("user");
        ObolPrincipal service = kdc.AddService(ServiceName);

        // The client tries TCP first, leave only UDP so the replies with a PAC are sent over it. Like MIT it
        // refuses to use UDP for a message over udp_preference_limit, the default 1465 is smaller than a reply with
        // a PAC.
        using KerberosClient client = kdc.CreateClient();
        client.Configuration.Defaults.UdpPreferenceLimit = KdcListener.DefaultMaxUdpReplySize;
        foreach (IKerberosTransport transport in client.Transports)
        {
            ((KerberosTransportBase)transport).Enabled = transport is UdpKerberosTransport;
        }
        await client.Authenticate(new KerberosPasswordCredential("user", TestKdc.Password, TestKdc.Realm));
        KrbApReq apReq = await client.GetServiceTicket(ServiceName);

        TestKdc.DecryptTicket(apReq.Ticket, service);
    }

    [Test]
    [Arguments(PrincipalNameType.NT_PRINCIPAL)]
    [Arguments(PrincipalNameType.NT_ENTERPRISE)]
    public async Task AuthenticatesWithNameType(PrincipalNameType nameType)
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");

        using KerberosClient client = kdc.CreateClient();
        KerberosPasswordCredential credential = new("user", TestKdc.Password, TestKdc.Realm)
        {
            PrincipalNameType = nameType,
        };
        await client.Authenticate(credential);
    }

    [Test]
    public async Task AuthenticatesWithEnterpriseNameLowerCaseSuffix()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");

        // Windows sends the UPN with the DNS domain which is usually lower case.
        using KerberosClient client = kdc.CreateClient();
        await client.Authenticate(new KerberosPasswordCredential("user@example.test", TestKdc.Password, TestKdc.Realm));
    }

    [Test]
    public async Task FailsWithEnterpriseNameOtherSuffix()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");

        using KerberosClient client = kdc.CreateClient();
        KerberosProtocolException ex = (await Assert.ThrowsAsync<KerberosProtocolException>(() =>
            client.Authenticate(new KerberosPasswordCredential("user@other.test", TestKdc.Password, TestKdc.Realm)
            {
                PrincipalNameType = PrincipalNameType.NT_PRINCIPAL,
            })))!;

        await Assert.That(ex.Error.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
    }

    [Test]
    public async Task FailsWithoutPreAuthWithUnsupportedEncryptionType()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user", flags: Kerberos.PacUserAccountControl.DontRequirePreAuth);

        // RC4 is not supported so the KDC has no key to encrypt the reply with. With pre-auth required the client
        // fails before reaching the KDC on Unix as it cannot derive an RC4 key without MD4.
        using KerberosClient client = kdc.CreateClient();
        client.Configuration.Defaults.AllowWeakCrypto = true;
        client.Configuration.Defaults.DefaultTicketEncTypes.Clear();
        client.Configuration.Defaults.DefaultTicketEncTypes.Add(EncryptionType.RC4_HMAC_NT);

        KerberosProtocolException ex = (await Assert.ThrowsAsync<KerberosProtocolException>(() =>
            client.Authenticate(new KerberosPasswordCredential("user", TestKdc.Password, TestKdc.Realm))))!;

        await Assert.That(ex.Error.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_ETYPE_NOSUPP);
    }

    [Test]
    public async Task AuthenticatesWithAlias()
    {
        using TestKdc kdc = new();
        ObolPrincipal principal = kdc.Store.Create(["HTTP", "test.com"], TestKdc.ToSecureString(TestKdc.Password),
            Kerberos.PacUserAccountControl.None, aliases: [["test"]]);

        // The keys use the salt of the principal's name, the client gets it from PA-ETYPE-INFO2.
        using KerberosClient client = kdc.CreateClient();
        await client.Authenticate(new KerberosPasswordCredential("test", TestKdc.Password, TestKdc.Realm));

        await Assert.That(principal.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!.Salt)
            .IsEqualTo("EXAMPLE.TESTHTTPtest.com");
    }

    [Test]
    public async Task FailsWithWrongPassword()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");

        using KerberosClient client = kdc.CreateClient();
        KerberosProtocolException ex = (await Assert.ThrowsAsync<KerberosProtocolException>(() =>
            client.Authenticate(new KerberosPasswordCredential("user", "wrong", TestKdc.Realm))))!;

        await Assert.That(ex.Error.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_PREAUTH_FAILED);
    }

    [Test]
    public async Task FailsWithUnknownUser()
    {
        using TestKdc kdc = new();

        using KerberosClient client = kdc.CreateClient();
        KerberosProtocolException ex = (await Assert.ThrowsAsync<KerberosProtocolException>(() =>
            client.Authenticate(new KerberosPasswordCredential("user", TestKdc.Password, TestKdc.Realm))))!;

        await Assert.That(ex.Error.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
    }

    [Test]
    public async Task FailsWithUnknownService()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");

        using KerberosClient client = kdc.CreateClient();
        await client.Authenticate(new KerberosPasswordCredential("user", TestKdc.Password, TestKdc.Realm));
        KerberosProtocolException ex = (await Assert.ThrowsAsync<KerberosProtocolException>(() =>
            client.GetServiceTicket(ServiceName)))!;

        await Assert.That(ex.Error.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }

    [Test]
    public async Task AuthenticatesWithoutPreAuth()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user", flags: Kerberos.PacUserAccountControl.DontRequirePreAuth);
        kdc.AddService(ServiceName);

        using KerberosClient client = kdc.CreateClient();
        await client.Authenticate(new KerberosPasswordCredential("user", TestKdc.Password, TestKdc.Realm));
        await client.GetServiceTicket(ServiceName);
    }

    [Test]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96)]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96)]
    public async Task AuthenticatesWithSingleEncryptionType(EncryptionType etype)
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");

        using KerberosClient client = kdc.CreateClient();
        client.Configuration.Defaults.DefaultTicketEncTypes.Clear();
        client.Configuration.Defaults.DefaultTicketEncTypes.Add(etype);
        await client.Authenticate(new KerberosPasswordCredential("user", TestKdc.Password, TestKdc.Realm));
    }

    [Test]
    public async Task MatchesNamesCaseSensitivelyByDefault()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");

        using KerberosClient client = kdc.CreateClient();
        KerberosProtocolException ex = (await Assert.ThrowsAsync<KerberosProtocolException>(() =>
            client.Authenticate(new KerberosPasswordCredential("USER", TestKdc.Password, TestKdc.Realm)
            {
                PrincipalNameType = PrincipalNameType.NT_PRINCIPAL,
            })))!;

        await Assert.That(ex.Error.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
    }

    [Test]
    public async Task MatchesNamesCaseInsensitively()
    {
        using TestKdc kdc = new(caseInsensitive: true);
        kdc.AddUser("user");
        kdc.AddService(ServiceName);

        // The salt is based on the name the principal was created with, the client gets it from PA-ETYPE-INFO2.
        using KerberosClient client = kdc.CreateClient();
        await client.Authenticate(new KerberosPasswordCredential("USER", TestKdc.Password, TestKdc.Realm)
        {
            PrincipalNameType = PrincipalNameType.NT_PRINCIPAL,
        });
        await client.GetServiceTicket(ServiceName.ToUpperInvariant());
    }

    [Test]
    public async Task RejectsDuplicateNames()
    {
        using TestKdc kdc = new(caseInsensitive: true);
        kdc.AddUser("user");

        await Assert.That(() => kdc.AddUser("USER")).Throws<PrincipalStoreException>();
        await Assert.That(() => kdc.AddService($"krbtgt/{TestKdc.Realm}")).Throws<PrincipalStoreException>();
    }

    [Test]
    public async Task CreatesKeysWithDefaultSalt()
    {
        using TestKdc kdc = new();
        ObolPrincipal user = kdc.AddUser("HTTP/web.example.test");

        // RFC 4120 4. the realm followed by each component.
        KerberosKey key = user.State.GetKey(Kerberos.EncryptionType.Aes256Sha1)!;
        await Assert.That(key.Salt).IsEqualTo("EXAMPLE.TESTHTTPweb.example.test");
        await Assert.That(user.Kvno).IsEqualTo(1);
        await Assert.That(user.EncryptionType).IsEquivalentTo(
            [Kerberos.EncryptionType.Aes256Sha1, Kerberos.EncryptionType.Aes128Sha1]);
    }
}
