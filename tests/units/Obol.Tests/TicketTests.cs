using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Obol.Tests;

/// <summary>The tickets the KDC issues to the Kerberos.NET client.</summary>
public class TicketTests
{
    private const string ServiceName = "HTTP/web.example.test";

    private static async Task<KerberosClient> Authenticate(TestKdc kdc, AuthenticationOptions? options = null,
        string user = "user", string password = TestKdc.Password)
    {
        KerberosClient client = kdc.CreateClient();
        if (options is AuthenticationOptions o)
        {
            client.AuthenticationOptions = o;
        }
        await client.Authenticate(new KerberosPasswordCredential(user, password, TestKdc.Realm));
        return client;
    }

    [Test]
    public async Task GrantsRequestedFlags()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");

        using KerberosClient client = await Authenticate(kdc);
        KerberosClientCacheEntry tgt = TestKdc.GetTgt(client);

        // The Kerberos.NET client asks for forwardable and renewable tickets by default.
        await Assert.That(tgt.Flags.HasFlag(TicketFlags.Initial)).IsTrue();
        await Assert.That(tgt.Flags.HasFlag(TicketFlags.PreAuthenticated)).IsTrue();
        await Assert.That(tgt.Flags.HasFlag(TicketFlags.Forwardable)).IsTrue();
        await Assert.That(tgt.Flags.HasFlag(TicketFlags.Renewable)).IsTrue();
        await Assert.That(tgt.RenewTill!.Value).IsGreaterThan(tgt.EndTime);
    }

    [Test]
    public async Task DoesNotGrantUnrequestedFlags()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");

        using KerberosClient client = await Authenticate(kdc,
            AuthenticationOptions.PreAuthenticate | AuthenticationOptions.IncludePacRequest);
        KerberosClientCacheEntry tgt = TestKdc.GetTgt(client);

        await Assert.That(tgt.Flags.HasFlag(TicketFlags.Forwardable)).IsFalse();
        await Assert.That(tgt.Flags.HasFlag(TicketFlags.Renewable)).IsFalse();
        await Assert.That(tgt.RenewTill).IsNull();
    }

    [Test]
    public async Task RenewsTgt()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");

        using KerberosClient client = await Authenticate(kdc);
        KerberosClientCacheEntry before = TestKdc.GetTgt(client);
        await Task.Delay(1100);
        await client.RenewTicket();
        KerberosClientCacheEntry after = TestKdc.GetTgt(client);

        await Assert.That(after.EndTime).IsGreaterThan(before.EndTime);
        await Assert.That(after.RenewTill).IsEqualTo(before.RenewTill);
        await Assert.That(after.Flags.HasFlag(TicketFlags.Renewable)).IsTrue();
        await Assert.That(after.Flags.HasFlag(TicketFlags.Initial)).IsFalse();
    }

    [Test]
    public async Task FailsToRenewTgtThatIsNotRenewable()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");

        using KerberosClient client = await Authenticate(kdc,
            AuthenticationOptions.PreAuthenticate | AuthenticationOptions.IncludePacRequest);
        KerberosProtocolException ex = (await Assert.ThrowsAsync<KerberosProtocolException>(() =>
            client.RenewTicket()))!;

        await Assert.That(ex.Error.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_BADOPTION);
    }

    [Test]
    public async Task ServiceTicketLimitedByTgt()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");
        ObolPrincipal service = kdc.AddService(ServiceName);

        using KerberosClient client = await Authenticate(kdc);
        KerberosClientCacheEntry tgt = TestKdc.GetTgt(client);
        KrbApReq apReq = await client.GetServiceTicket(ServiceName);
        KrbEncTicketPart ticket = TestKdc.DecryptTicket(apReq.Ticket, service);

        await Assert.That(ticket.EndTime).IsLessThanOrEqualTo(tgt.EndTime);
        await Assert.That(ticket.RenewTill!.Value).IsLessThanOrEqualTo(tgt.RenewTill!.Value);
        await Assert.That(ticket.Flags.HasFlag(TicketFlags.Initial)).IsFalse();
        await Assert.That(ticket.Flags.HasFlag(TicketFlags.PreAuthenticated)).IsTrue();
    }

    [Test]
    public async Task IssuesTicketForAlias()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");
        ObolPrincipal service = kdc.AddService(ServiceName, aliases: ["HTTP/web"]);

        using KerberosClient client = await Authenticate(kdc);
        KrbApReq apReq = await client.GetServiceTicket("HTTP/web");

        // The ticket has the requested name and is encrypted with the principal's key.
        await Assert.That(apReq.Ticket.SName.FullyQualifiedName).IsEqualTo("HTTP/web");
        TestKdc.DecryptTicket(apReq.Ticket, service);
    }

    [Test]
    public async Task LimitsSessionKeyToServiceEncryptionTypes()
    {
        using TestKdc kdc = new();
        kdc.AddUser("user");
        ObolPrincipal service = kdc.AddService(ServiceName, [EncryptionType.AES128_CTS_HMAC_SHA1_96]);

        using KerberosClient client = await Authenticate(kdc);
        KrbApReq apReq = await client.GetServiceTicket(ServiceName);
        KrbEncTicketPart ticket = TestKdc.DecryptTicket(apReq.Ticket, service);

        await Assert.That(apReq.Ticket.EncryptedPart.EType).IsEqualTo(EncryptionType.AES128_CTS_HMAC_SHA1_96);
        await Assert.That(ticket.Key.EType).IsEqualTo(EncryptionType.AES128_CTS_HMAC_SHA1_96);
    }

    [Test]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192)]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128)]
    public async Task AuthenticatesWithSha2Keys(EncryptionType etype)
    {
        using TestKdc kdc = new();
        kdc.AddUser("user", encryptionTypes: [etype]);
        ObolPrincipal service = kdc.AddService(ServiceName, [etype]);

        using KerberosClient client = await Authenticate(kdc);
        KrbApReq apReq = await client.GetServiceTicket(ServiceName);

        await Assert.That(apReq.Ticket.EncryptedPart.EType).IsEqualTo(etype);
        TestKdc.DecryptTicket(apReq.Ticket, service);
    }

    [Test]
    public async Task UsesNewKeysAfterUpdate()
    {
        using TestKdc kdc = new();
        ObolPrincipal user = kdc.AddUser("user");
        ObolPrincipal service = kdc.AddService(ServiceName);

        kdc.Store.Update(user, password: TestKdc.ToSecureString("NewPassword1!"));
        kdc.Store.Update(service, newRandomKey: true);

        KerberosProtocolException ex = (await Assert.ThrowsAsync<KerberosProtocolException>(() =>
            Authenticate(kdc)))!;
        await Assert.That(ex.Error.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_PREAUTH_FAILED);

        using KerberosClient client = await Authenticate(kdc, password: "NewPassword1!");
        KrbApReq apReq = await client.GetServiceTicket(ServiceName);

        await Assert.That(apReq.Ticket.EncryptedPart.KeyVersionNumber).IsEqualTo(2);
        TestKdc.DecryptTicket(apReq.Ticket, service);
    }

    [Test]
    public async Task AuthenticatesWithoutPreAuthAfterUpdate()
    {
        using TestKdc kdc = new();
        ObolPrincipal user = kdc.AddUser("user");

        kdc.Store.Update(user, flags: Kerberos.PacUserAccountControl.DontRequirePreAuth);

        using KerberosClient client = await Authenticate(kdc,
            AuthenticationOptions.IncludePacRequest | AuthenticationOptions.Renewable);
        KerberosClientCacheEntry tgt = TestKdc.GetTgt(client);

        await Assert.That(tgt.Flags.HasFlag(TicketFlags.PreAuthenticated)).IsFalse();
    }

    [Test]
    public async Task FailsForRemovedPrincipals()
    {
        using TestKdc kdc = new();
        ObolPrincipal user = kdc.AddUser("user");
        ObolPrincipal service = kdc.AddService(ServiceName);

        using KerberosClient client = await Authenticate(kdc);
        kdc.Store.Remove(service);

        KerberosProtocolException ex = (await Assert.ThrowsAsync<KerberosProtocolException>(() =>
            client.GetServiceTicket(ServiceName)))!;
        await Assert.That(ex.Error.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN);

        // A TGT of a removed client cannot be used for new tickets.
        kdc.AddService(ServiceName);
        kdc.Store.Remove(user);
        ex = (await Assert.ThrowsAsync<KerberosProtocolException>(() => client.GetServiceTicket(ServiceName)))!;
        await Assert.That(ex.Error.ErrorCode).IsEqualTo(KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
    }
}
