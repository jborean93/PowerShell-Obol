using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Obol.Protocol;

namespace Obol.Tests;

public class PrincipalStoreTests
{
    private static PrincipalStore CreateStore(bool caseInsensitive = false) => new("EXAMPLE.TEST", caseInsensitive);

    private static ObolPrincipal AddService(PrincipalStore store, string name, params string[] aliases)
        => store.Create(name.Split('/'), null, ObolPrincipalFlag.None, null,
            [.. System.Linq.Enumerable.Select(aliases, a => a.Split('/'))]);

    private static async Task AssertStoreError(System.Action action, PrincipalStoreError error)
    {
        PrincipalStoreException ex = (await Assert.That(action).Throws<PrincipalStoreException>())!;
        await Assert.That(ex.Error).IsEqualTo(error);
    }

    [Test]
    public async Task ReusesRidOfRemovedPrincipalOnlyWhenSet()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal first = AddService(store, "HTTP/first");
        store.Remove(first);

        ObolPrincipal second = AddService(store, "HTTP/second");
        ObolPrincipal third = store.Create(["HTTP", "third"], null, ObolPrincipalFlag.None, rid: 1000);

        await Assert.That(second.Sid).IsEqualTo($"{store.DomainSid}-1001");
        await Assert.That(third.Sid).IsEqualTo($"{store.DomainSid}-1000");
    }

    [Test]
    public async Task RejectsRidInUse()
    {
        PrincipalStore store = CreateStore();
        AddService(store, "HTTP/first");

        await AssertStoreError(() => store.Create(["HTTP", "second"], null, ObolPrincipalFlag.None, rid: 1000),
            PrincipalStoreError.RidAlreadyUsed);
    }

    [Test]
    [Arguments("S-1-5-21-1-2-3", true)]
    [Arguments("s-1-5-21-0-0-4294967295", true)]
    [Arguments("S-1-5-21-1-2", false)]
    [Arguments("S-1-5-21-1-2-3-4", false)]
    [Arguments("S-1-5-21-+1-2-3", false)]
    [Arguments("S-1-5-21- 1-2-3", false)]
    [Arguments("S-1-5-21-1-2-4294967296", false)]
    [Arguments("S-1-5-32-1-2-3", false)]
    public async Task ParsesDomainSid(string value, bool expected)
    {
        await Assert.That(PrincipalStore.TryParseDomainSid(value, out _)).IsEqualTo(expected);
    }

    [Test]
    [Arguments(
        "Password123!",
        "cc7517320a9c6cd13de0ea137e9fe17e5724178754077af2a8c9ca80dd582a90",
        "25bd781ec92083ac830b18f2dced9315",
        "bea2482ec3ab30a1e78085fa528a8ce7142f03fdf006f41b955133a5cd6951d8",
        "ddfdb559721f32c1240fea390e83df2a")]
    [Arguments(
        "p\u00e4ssword",
        "29406e503512ddb3d554def0af722ab8bd44941e6bd8ff6749c046a18be78684",
        "59741debd0159457d775e0ff8209b3d3",
        "dbc43b6a1e082bbfef1558f0bd8290a8dfd281756963d80cede18d6e59bb18dc",
        "5b29ccd0c8c53c49a669fbb4c67ac783")]
    [Arguments(
        "\U0001D11E",
        "73c1e2e3d68c046f604cd0bced63dd04e4ecf0cc500887f1f5cf087dee6ccdaf",
        "c1947dae47946e45aca8cc01a39225d0",
        "094c994cdf7270d54fbe2cd538b03a7766d40ecc75dcddca224aa34e10e3613f",
        "3d9b9a9ace2015ce1fa153ef61a06e2c")]
    public async Task DerivesKeysLikeMit(
        string password,
        string aes256Sha1,
        string aes128Sha1,
        string aes256Sha384,
        string aes128Sha256)
    {
        // The keys MIT ktutil addent -password creates for user@EXAMPLE.TEST with the default salt and iteration
        // count. The last password is a G clef outside the BMP, a surrogate pair in the SecureString.
        PrincipalStore store = CreateStore();
        ObolPrincipal user = store.Create(["user"], TestKdc.ToSecureString(password), ObolPrincipalFlag.None,
        [
            ObolEncryptionType.Aes256Sha1,
            ObolEncryptionType.Aes128Sha1,
            ObolEncryptionType.Aes256Sha384,
            ObolEncryptionType.Aes128Sha256,
        ]);

        await Assert.That(KeyHex(user, EncryptionType.AES256_CTS_HMAC_SHA1_96)).IsEqualTo(aes256Sha1);
        await Assert.That(KeyHex(user, EncryptionType.AES128_CTS_HMAC_SHA1_96)).IsEqualTo(aes128Sha1);
        await Assert.That(KeyHex(user, EncryptionType.AES256_CTS_HMAC_SHA384_192)).IsEqualTo(aes256Sha384);
        await Assert.That(KeyHex(user, EncryptionType.AES128_CTS_HMAC_SHA256_128)).IsEqualTo(aes128Sha256);
    }

    private static string KeyHex(ObolPrincipal principal, EncryptionType etype)
        => System.Convert.ToHexStringLower(principal.State.GetKey(etype)!.GetKey().Span);

    [Test]
    public async Task RejectsUnknownEncryptionType()
    {
        PrincipalStore store = CreateStore();

        // The cmdlets reject undefined values, the store still fails if one gets through.
        await Assert.That(() => store.Create(["HTTP", "web"], null, ObolPrincipalFlag.None, [(ObolEncryptionType)99]))
            .Throws<System.ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task FailsToEncodeUnmappedEncryptionType()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal service = AddService(store, "HTTP/web");
        service.State = new PrincipalState(
            [new KerberosKey(key: new byte[16], etype: EncryptionType.RC4_HMAC_NT, kvno: 1)],
            1,
            ObolPrincipalFlag.None,
            []);

        await Assert.That(() => new KdcPrincipal(service).EncodeSupportedEncryptionTypes())
            .Throws<System.ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task FindsByAlias()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal service = AddService(store, "HTTP/web.example.test", "HTTP/web");

        await Assert.That(store.Find(["HTTP", "web"])).IsSameReferenceAs(service);
        await Assert.That(store.Find(["HTTP", "web.example.test"])).IsSameReferenceAs(service);
        await Assert.That(service.Alias).IsEquivalentTo(["HTTP/web"]);
    }

    [Test]
    [Arguments("HTTP/web.example.test")]
    [Arguments("krbtgt/EXAMPLE.TEST")]
    [Arguments("HTTP/other")]
    public async Task RejectsAliasInUse(string alias)
    {
        PrincipalStore store = CreateStore();
        AddService(store, "HTTP/other");

        await AssertStoreError(() => AddService(store, "HTTP/web.example.test", alias),
            PrincipalStoreError.AlreadyExists);
    }

    [Test]
    public async Task RejectsDuplicateAliases()
    {
        PrincipalStore store = CreateStore();

        await AssertStoreError(() => AddService(store, "HTTP/web.example.test", "HTTP/web", "HTTP/web"),
            PrincipalStoreError.AlreadyExists);
        await Assert.That(store.Find(["HTTP", "web.example.test"])).IsNull();
    }

    [Test]
    public async Task RejectsAliasDifferingByCaseWhenInsensitive()
    {
        PrincipalStore store = CreateStore(caseInsensitive: true);
        AddService(store, "HTTP/web");

        await AssertStoreError(() => AddService(store, "HTTP/web.example.test", "http/WEB"),
            PrincipalStoreError.AlreadyExists);
    }

    [Test]
    public async Task ReplacesAliases()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal service = AddService(store, "HTTP/web.example.test", "HTTP/web", "HTTP/old");

        store.Update(service, aliases: [["HTTP", "web"], ["HTTP", "new"]]);

        await Assert.That(store.Find(["HTTP", "old"])).IsNull();
        await Assert.That(store.Find(["HTTP", "web"])).IsSameReferenceAs(service);
        await Assert.That(store.Find(["HTTP", "new"])).IsSameReferenceAs(service);
        await Assert.That(service.Kvno).IsEqualTo(1);
    }

    [Test]
    public async Task KeepsAliasesWhenReplaceFails()
    {
        PrincipalStore store = CreateStore();
        AddService(store, "HTTP/other");
        ObolPrincipal service = AddService(store, "HTTP/web.example.test", "HTTP/web");

        await AssertStoreError(() => store.Update(service, aliases: [["HTTP", "other"]]),
            PrincipalStoreError.AlreadyExists);
        await Assert.That(store.Find(["HTTP", "web"])).IsSameReferenceAs(service);
    }

    [Test]
    public async Task IncrementsKvnoForNewKeys()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal service = AddService(store, "HTTP/web");
        byte[] oldKey = service.State.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96)!.GetKey().ToArray();

        store.Update(service, newRandomKey: true);

        KerberosKey newKey = service.State.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96)!;
        await Assert.That(service.Kvno).IsEqualTo(2);
        await Assert.That(newKey.Version).IsEqualTo(2);
        await Assert.That(newKey.GetKey().ToArray()).IsNotEquivalentTo(oldKey);
    }

    [Test]
    public async Task KeepsSubsetOfEncryptionTypesWithoutNewKeys()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal service = AddService(store, "HTTP/web");

        store.Update(service, encryptionTypes: [ObolEncryptionType.Aes128Sha1]);

        await Assert.That(service.EncryptionType).IsEquivalentTo([ObolEncryptionType.Aes128Sha1]);
        await Assert.That(service.Kvno).IsEqualTo(1);
    }

    [Test]
    public async Task RequiresNewKeysToAddEncryptionType()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal service = AddService(store, "HTTP/web");

        await AssertStoreError(
            () => store.Update(service, encryptionTypes: [ObolEncryptionType.Aes256Sha384]),
            PrincipalStoreError.InvalidEncryptionType);

        store.Update(service, newRandomKey: true, encryptionTypes: [ObolEncryptionType.Aes256Sha384]);
        await Assert.That(service.EncryptionType).IsEquivalentTo([ObolEncryptionType.Aes256Sha384]);
    }

    [Test]
    public async Task RejectsChangesToRemovedPrincipal()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal service = AddService(store, "HTTP/web.example.test", "HTTP/web");

        store.Remove(service);

        await Assert.That(store.Find(["HTTP", "web.example.test"])).IsNull();
        await Assert.That(store.Find(["HTTP", "web"])).IsNull();
        await Assert.That(store.Principals).DoesNotContain(service);
        await AssertStoreError(() => store.Update(service, newRandomKey: true), PrincipalStoreError.NotFound);
        await AssertStoreError(() => store.Remove(service), PrincipalStoreError.NotFound);
    }

    [Test]
    public async Task ReusesNameAfterRemove()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal old = AddService(store, "HTTP/web");
        store.Remove(old);

        ObolPrincipal service = AddService(store, "HTTP/web");

        await Assert.That(store.Find(["HTTP", "web"])).IsSameReferenceAs(service);
        await AssertStoreError(() => store.Update(old, newRandomKey: true), PrincipalStoreError.NotFound);
    }

    [Test]
    public async Task ProtectsKrbtgt()
    {
        PrincipalStore store = CreateStore();

        await AssertStoreError(() => store.Remove(store.Krbtgt), PrincipalStoreError.Krbtgt);
        await AssertStoreError(() => store.Update(store.Krbtgt, aliases: [["krbtgt", "OTHER"]]),
            PrincipalStoreError.Krbtgt);

        // New keys are allowed, which makes existing TGTs invalid.
        store.Update(store.Krbtgt, newRandomKey: true);
        await Assert.That(store.Krbtgt.Kvno).IsEqualTo(2);
    }

    [Test]
    public async Task CreatesPrincipalWithImportedKeys()
    {
        PrincipalStore store = CreateStore();
        byte[] aes128 = [.. Enumerable.Range(0, 16).Select(i => (byte)i)];
        byte[] aes256 = [.. Enumerable.Range(0, 32).Select(i => (byte)(i + 100))];

        ObolPrincipal principal = store.Create(["HTTP", "web"], null, ObolPrincipalFlag.None, salt: "CUSTOMsalt",
            importedKeys: new ImportedKeys(7,
                [(ObolEncryptionType.Aes128Sha1, aes128), (ObolEncryptionType.Aes256Sha1, aes256)]));

        await Assert.That(principal.Kvno).IsEqualTo(7);
        await Assert.That(principal.Salt).IsEqualTo("CUSTOMsalt");
        await Assert.That(principal.EncryptionType).IsEquivalentTo(
            [ObolEncryptionType.Aes128Sha1, ObolEncryptionType.Aes256Sha1]);
        await Assert.That(KeyHex(principal, EncryptionType.AES128_CTS_HMAC_SHA1_96))
            .IsEqualTo(System.Convert.ToHexStringLower(aes128));
        await Assert.That(principal.State.Keys.Select(k => k.Version)).IsEquivalentTo(new int?[] { 7, 7 });
    }

    [Test]
    public async Task ImportedKeysUseDefaultSalt()
    {
        PrincipalStore store = CreateStore();

        ObolPrincipal principal = store.Create(["HTTP", "web"], null, ObolPrincipalFlag.None,
            importedKeys: new ImportedKeys(1, [(ObolEncryptionType.Aes128Sha1, new byte[16])]));

        await Assert.That(principal.Salt).IsEqualTo("EXAMPLE.TESTHTTPweb");
    }

    [Test]
    public async Task UpdateWithImportedKeysSetsKvno()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal principal = AddService(store, "HTTP/web");
        store.Update(principal, newRandomKey: true);
        store.Update(principal, newRandomKey: true);

        // A keytab can have an older kvno than the principal, the keys keep the keytab kvno.
        store.Update(principal, importedKeys: new ImportedKeys(1, [(ObolEncryptionType.Aes256Sha1, new byte[32])]));

        await Assert.That(principal.Kvno).IsEqualTo(1);
        await Assert.That(principal.EncryptionType).IsEquivalentTo([ObolEncryptionType.Aes256Sha1]);
        await Assert.That(principal.State.Keys[0].Version).IsEqualTo(1);
    }

    [Test]
    public async Task DerivesPasswordKeysWithSalt()
    {
        // ktutil addent -password -s 'CORP.EXAMPLEsvc_web' -e aes256-cts-hmac-sha1-96 with 'Password123!'.
        PrincipalStore store = CreateStore();

        ObolPrincipal principal = store.Create(["HTTP", "web"], TestKdc.ToSecureString("Password123!"),
            ObolPrincipalFlag.None, [ObolEncryptionType.Aes256Sha1], salt: "CORP.EXAMPLEsvc_web");

        await Assert.That(principal.Salt).IsEqualTo("CORP.EXAMPLEsvc_web");
        await Assert.That(KeyHex(principal, EncryptionType.AES256_CTS_HMAC_SHA1_96))
            .IsEqualTo("ab8c3a5300b091e044f72526e1669fa999e4cb152042325df4f4864ffdf38e5c");
    }

    [Test]
    public async Task UpdatePasswordWithSalt()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal principal = AddService(store, "HTTP/web");

        store.Update(principal, TestKdc.ToSecureString("Password123!"),
            encryptionTypes: [ObolEncryptionType.Aes256Sha1], salt: "CORP.EXAMPLEsvc_web");

        await Assert.That(principal.Kvno).IsEqualTo(2);
        await Assert.That(KeyHex(principal, EncryptionType.AES256_CTS_HMAC_SHA1_96))
            .IsEqualTo("ab8c3a5300b091e044f72526e1669fa999e4cb152042325df4f4864ffdf38e5c");
    }

    [Test]
    public async Task CreatesPrincipalWithKvno()
    {
        PrincipalStore store = CreateStore();

        ObolPrincipal principal = store.Create(["HTTP", "web"], TestKdc.ToSecureString("Password123!"),
            ObolPrincipalFlag.None, kvno: 300);

        await Assert.That(principal.Kvno).IsEqualTo(300);
        await Assert.That(principal.State.Keys.Select(k => k.Version)).IsEquivalentTo(new int?[] { 300, 300 });
    }

    [Test]
    public async Task UpdateNewKeysWithKvno()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal principal = AddService(store, "HTTP/web");

        store.Update(principal, newRandomKey: true, kvno: 9);

        await Assert.That(principal.Kvno).IsEqualTo(9);
        await Assert.That(principal.State.Keys.Select(k => k.Version)).IsEquivalentTo(new int?[] { 9, 9 });
    }

    [Test]
    public async Task UpdateKvnoKeepsKeys()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal principal = AddService(store, "HTTP/web");
        string before = KeyHex(principal, EncryptionType.AES256_CTS_HMAC_SHA1_96);

        store.Update(principal, kvno: 20);

        await Assert.That(principal.Kvno).IsEqualTo(20);
        await Assert.That(principal.State.Keys.Select(k => k.Version)).IsEquivalentTo(new int?[] { 20, 20 });
        await Assert.That(KeyHex(principal, EncryptionType.AES256_CTS_HMAC_SHA1_96)).IsEqualTo(before);
    }

    [Test]
    public async Task UpdateSameKvnoKeepsState()
    {
        PrincipalStore store = CreateStore();
        ObolPrincipal principal = AddService(store, "HTTP/web");
        PrincipalState before = principal.State;

        store.Update(principal, kvno: 1);

        await Assert.That(principal.State.Keys).IsEquivalentTo(before.Keys);
    }
}
