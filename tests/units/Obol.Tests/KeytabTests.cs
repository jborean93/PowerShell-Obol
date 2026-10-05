using System;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Obol.Protocol;

namespace Obol.Tests;

public class KeytabTests
{
    private static byte[] Write(DateTimeOffset timestamp, params ObolPrincipal[] principals)
    {
        ArrayBufferWriter<byte> writer = new();
        writer.Write(Keytab.Header);
        foreach (ObolPrincipal principal in principals)
        {
            foreach (ObolKeytabEntry entry in Keytab.GetEntries(principal, timestamp.UtcDateTime))
            {
                Keytab.WriteEntry(writer, entry);
            }
        }
        return writer.WrittenSpan.ToArray();
    }

    [Test]
    public async Task WritesMitFormat()
    {
        // Laid out by hand from the MIT "Keytab file format" documentation.
        PrincipalStore store = new("R", false);
        byte[] key = [.. Enumerable.Range(0, 16).Select(i => (byte)i)];
        PrincipalState state = new(
            [new KerberosKey(key: key, etype: EncryptionType.AES128_CTS_HMAC_SHA1_96, kvno: 1)],
            1,
            Kerberos.PacUserAccountControl.None,
            []);
        ObolPrincipal principal = new(store, ["host", "a"], state, 1000, "S-1-5-21-1-2-3-1000");

        byte[] actual = Write(DateTimeOffset.FromUnixTimeSeconds(0x01020304), principal);

        string expected =
            "0502" + // file version
            "0000002f" + // entry length
            "0002" + // component count
            "000152" + // realm R
            "0004686f7374" + // host
            "000161" + // a
            "00000001" + // KRB5_NT_PRINCIPAL
            "01020304" + // timestamp
            "01" + // 8-bit kvno
            "0011" + // aes128-cts-hmac-sha1-96
            "0010000102030405060708090a0b0c0d0e0f" + // key
            "00000001"; // 32-bit kvno
        await Assert.That(Convert.ToHexStringLower(actual)).IsEqualTo(expected);
    }

    [Test]
    public async Task WritesEveryKeyForNameAndAliases()
    {
        PrincipalStore store = new("EXAMPLE.TEST", false);
        ObolPrincipal principal = store.Create(
            ["HTTP", "web.example.test"],
            null,
            Kerberos.PacUserAccountControl.None,
            [Kerberos.EncryptionType.Aes256Sha384, Kerberos.EncryptionType.Aes128Sha1],
            [["HTTP", "web"], ["HTTP", "a/b@c"]]);
        DateTimeOffset timestamp = DateTimeOffset.FromUnixTimeSeconds(1790000000);

        byte[] data = Write(timestamp, principal);
        KeyTable keytab = new(data);

        KeyEntry[] entries = [.. keytab.Entries];
        await Assert.That(keytab.FileVersion).IsEqualTo(2);
        await Assert.That(entries.Select(e => e.Principal.FullyQualifiedName)).IsEquivalentTo(
        [
            "HTTP/web.example.test", "HTTP/web.example.test",
            "HTTP/web", "HTTP/web",
            "HTTP/a/b@c", "HTTP/a/b@c",
        ]);

        // Kerberos.NET joins the components with '/' when reading, check the escaped alias is one component.
        byte[] component = [0x00, 0x05, .. "a/b@c"u8];
        await Assert.That(data.AsSpan().IndexOf(component)).IsGreaterThan(0);
        foreach (KeyEntry entry in entries)
        {
            await Assert.That(entry.Principal.Realm).IsEqualTo("EXAMPLE.TEST");
            await Assert.That(entry.Timestamp).IsEqualTo(timestamp);
            await Assert.That(entry.Version).IsEqualTo(1);

            KerberosKey expected = principal.State.GetKey(entry.EncryptionType!.Value.ToObol())!;
            await Assert.That(entry.Key.GetKey().ToArray()).IsEquivalentTo(expected.GetKey().ToArray());
        }
        await Assert.That(entries.Select(e => e.EncryptionType!.Value).Distinct()).IsEquivalentTo(
            [EncryptionType.AES256_CTS_HMAC_SHA384_192, EncryptionType.AES128_CTS_HMAC_SHA1_96]);
    }

    [Test]
    public async Task WritesKvnoOver255()
    {
        PrincipalStore store = new("EXAMPLE.TEST", false);
        ObolPrincipal principal = store.Create(["user"], null, Kerberos.PacUserAccountControl.None);
        for (int i = 0; i < 300; i++)
        {
            store.Update(principal, newRandomKey: true);
        }

        byte[] data = Write(DateTimeOffset.UtcNow, principal);

        // The 8-bit kvno has the low byte, readers use the 32-bit value at the end of the entry.
        KeyEntry entry = new KeyTable(data).Entries.First();
        await Assert.That(entry.Version).IsEqualTo(301);
        int entryLength = (data[2] << 24) | (data[3] << 16) | (data[4] << 8) | data[5];
        int vno8Offset = 6 + entryLength - 4 - (2 + 2 + 32) - 1;
        await Assert.That(data[vno8Offset]).IsEqualTo((byte)(301 & 0xFF));
    }

    [Test]
    public async Task ReadsWhatItWrites()
    {
        PrincipalStore store = new("EXAMPLE.TEST", false);
        ObolPrincipal principal = store.Create(["HTTP", "a/b"], null, Kerberos.PacUserAccountControl.None, null,
            [["HTTP", "c"]]);
        store.Update(principal, newRandomKey: true);
        DateTimeOffset timestamp = DateTimeOffset.FromUnixTimeSeconds(1790000000);

        ObolKeytabEntry[] entries = [.. Keytab.Read(Write(timestamp, principal))];

        await Assert.That(entries.Select(e => e.FullName)).IsEquivalentTo(
            [@"HTTP/a\/b@EXAMPLE.TEST", @"HTTP/a\/b@EXAMPLE.TEST", "HTTP/c@EXAMPLE.TEST", "HTTP/c@EXAMPLE.TEST"]);
        await Assert.That(entries[0].Components).IsEquivalentTo(["HTTP", "a/b"]);
        await Assert.That(entries.Select(e => e.EncryptionType)).IsEquivalentTo(
            [Kerberos.EncryptionType.Aes256Sha1, Kerberos.EncryptionType.Aes128Sha1,
                Kerberos.EncryptionType.Aes256Sha1, Kerberos.EncryptionType.Aes128Sha1]);
        foreach (ObolKeytabEntry entry in entries)
        {
            await Assert.That(entry.Kvno).IsEqualTo(2);
            await Assert.That(entry.NameType).IsEqualTo(Kerberos.PrincipalNameType.Principal);
            await Assert.That(entry.Timestamp.ToUniversalTime()).IsEqualTo(timestamp.UtcDateTime);
            await Assert.That(entry.Timestamp.Kind).IsEqualTo(DateTimeKind.Local);
            await Assert.That(entry.Key).IsEquivalentTo(
                principal.State.GetKey(entry.EncryptionType)!.GetKey().ToArray());
        }
    }

    /// <summary>An entry for host/a@R with a 16 byte key of etype 17, without the 32-bit kvno.</summary>
    private static byte[] RawEntry(byte kvno8, byte[] trailer, ushort etype = 17, int keyLength = 16)
    {
        byte[] body = [
            0x00, 0x02, 0x00, 0x01, (byte)'R', 0x00, 0x04, (byte)'h', (byte)'o', (byte)'s', (byte)'t',
            0x00, 0x01, (byte)'a', 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, kvno8,
            (byte)(etype >> 8), (byte)etype, (byte)(keyLength >> 8), (byte)keyLength,
            .. new byte[keyLength], .. trailer,
        ];
        return [(byte)(body.Length >> 24), (byte)(body.Length >> 16), (byte)(body.Length >> 8), (byte)body.Length,
            .. body];
    }

    [Test]
    [Arguments(new byte[0], 7)]
    [Arguments(new byte[] { 0, 0, 0, 0 }, 7)]
    [Arguments(new byte[] { 0, 0, 1, 7 }, 263)]
    [Arguments(new byte[] { 0, 0, 0, 9, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 }, 9)]
    public async Task ReadsKvno(byte[] trailer, int expected)
    {
        // A missing or 0 32-bit kvno uses the 8-bit kvno, bytes after it (Heimdal extensions) are ignored.
        byte[] data = [0x05, 0x02, .. RawEntry(7, trailer)];

        ObolKeytabEntry entry = Keytab.Read(data).Single();

        await Assert.That(entry.Kvno).IsEqualTo(expected);
        await Assert.That(entry.FullName).IsEqualTo("host/a@R");
        await Assert.That(entry.Timestamp.ToUniversalTime()).IsEqualTo(DateTime.UnixEpoch.AddSeconds(0x01020304));
    }

    [Test]
    public async Task SkipsDeletedEntries()
    {
        // MIT marks a removed entry with a negative length so the space can be reused.
        byte[] hole = [0xFF, 0xFF, 0xFF, 0xF6, .. new byte[10]];
        byte[] data = [0x05, 0x02, .. hole, .. RawEntry(3, []), .. hole];

        ObolKeytabEntry entry = Keytab.Read(data).Single();

        await Assert.That(entry.Kvno).IsEqualTo(3);
    }

    [Test]
    public async Task ReadsUnknownEncryptionType()
    {
        byte[] data = [0x05, 0x02, .. RawEntry(1, [], etype: 23)];

        ObolKeytabEntry entry = Keytab.Read(data).Single();

        await Assert.That((int)entry.EncryptionType).IsEqualTo(23);
    }

    [Test]
    public async Task ReadsEmptyKeytab()
    {
        await Assert.That(Keytab.Read([0x05, 0x02])).IsEmpty();
    }

    [Test]
    [Arguments(new byte[0], "*version is none*")]
    [Arguments(new byte[] { 0x05, 0x01 }, "*version is 0x0501*")]
    [Arguments(new byte[] { 0x05, 0x02, 0x00 }, "*entry length at offset 2 is truncated*")]
    [Arguments(new byte[] { 0x05, 0x02, 0x00, 0x00, 0x00, 0x10, 0x00 }, "*past the end*")]
    [Arguments(new byte[] { 0x05, 0x02, 0x80, 0x00, 0x00, 0x00 }, "*past the end*")]
    [Arguments(new byte[] { 0x05, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00 }, "*offset 6 is truncated*")]
    public async Task RejectsInvalidData(byte[] data, string message)
    {
        InvalidDataException ex = (await Assert.That(() => Keytab.Read(data)).Throws<InvalidDataException>())!;

        await Assert.That(ex.Message).Matches(
            "^" + System.Text.RegularExpressions.Regex.Escape(message).Replace(@"\*", ".*") + "$");
    }

    [Test]
    public async Task RejectsTruncatedKey()
    {
        byte[] entry = RawEntry(1, []);
        // Claim a 32 byte key in an entry that only has 16.
        entry[4 + 26] = 32;

        await Assert.That(() => Keytab.Read([0x05, 0x02, .. entry])).Throws<InvalidDataException>();
    }

    [Test]
    public async Task RejectsEntryWithoutComponents()
    {
        byte[] entry = RawEntry(1, []);
        entry[5] = 0;

        await Assert.That(() => Keytab.Read([0x05, 0x02, .. entry])).Throws<InvalidDataException>();
    }

    [Test]
    public async Task WritesReadEntriesUnchanged()
    {
        // Name type, timestamp, kvno over 255 and an unsupported encryption type are kept, so a keytab read and
        // written again is the same bytes.
        byte[] data = [0x05, 0x02, .. RawEntry(7, [0, 0, 1, 7], etype: 23), .. RawEntry(1, [0, 0, 0, 1])];
        data[4 + 17] = 2; // name type KRB5_NT_SRV_INST of the first entry

        ArrayBufferWriter<byte> writer = new();
        writer.Write(Keytab.Header);
        foreach (ObolKeytabEntry entry in Keytab.Read(data))
        {
            Keytab.WriteEntry(writer, entry);
        }

        await Assert.That(Convert.ToHexString(writer.WrittenSpan)).IsEqualTo(Convert.ToHexString(data));
    }

    [Test]
    public async Task WritesLocalTimestampAsUtc()
    {
        // The entry shows local time, the keytab must hold the same instant in UTC seconds.
        PrincipalStore store = new("R", false);
        ObolPrincipal principal = store.Create(["a"], null, Kerberos.PacUserAccountControl.None,
            [Kerberos.EncryptionType.Aes128Sha1]);
        DateTime utc = DateTime.UnixEpoch.AddSeconds(0x01020304);
        ObolKeytabEntry entry = Keytab.GetEntries(principal, utc).Single();

        ArrayBufferWriter<byte> writer = new();
        Keytab.WriteEntry(writer, entry);

        await Assert.That(entry.Timestamp.Kind).IsEqualTo(DateTimeKind.Local);
        // length, component count, realm "R", component "a", name type, then the timestamp
        int offset = 4 + 2 + 3 + 3 + 4;
        await Assert.That(Convert.ToHexString(writer.WrittenSpan.Slice(offset, 4))).IsEqualTo("01020304");
    }

    [Test]
    public async Task RejectsKvnoTooLargeForInt()
    {
        byte[] data = [0x05, 0x02, .. RawEntry(1, [0x80, 0x00, 0x00, 0x00])];

        InvalidDataException ex = (await Assert.That(() => Keytab.Read(data)).Throws<InvalidDataException>())!;

        await Assert.That(ex.Message).Contains("has a kvno of 2147483648 which is too large");
    }

    [Test]
    public async Task RejectsEntryEndingBeforeKvno()
    {
        // The entry ends after the timestamp, reading the 8-bit kvno goes past it.
        byte[] body = [
            0x00, 0x01, 0x00, 0x01, (byte)'R', 0x00, 0x01, (byte)'a', 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04,
        ];
        byte[] data = [0x05, 0x02, 0x00, 0x00, 0x00, (byte)body.Length, .. body];

        InvalidDataException ex = (await Assert.That(() => Keytab.Read(data)).Throws<InvalidDataException>())!;

        await Assert.That(ex.Message).IsEqualTo("The entry at offset 6 is truncated");
    }

    [Test]
    public async Task RejectsComponentTooLongToWrite()
    {
        ObolKeytabEntry entry = new("R", ["HTTP", new string('a', ushort.MaxValue + 1)],
            Kerberos.PrincipalNameType.Principal, DateTime.UtcNow, 1, Kerberos.EncryptionType.Aes128Sha1, new byte[16]);

        ArgumentException ex = (await Assert.That(() => Keytab.WriteEntry(new ArrayBufferWriter<byte>(), entry))
            .Throws<ArgumentException>())!;

        await Assert.That(ex.Message).Contains("65536 bytes is too long for a keytab");
    }
}

