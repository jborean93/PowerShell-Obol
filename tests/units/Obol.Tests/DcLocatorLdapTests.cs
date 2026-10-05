using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Obol.Tests;

/// <summary>The replies to the CLDAP LDAP ping of the DC locator.</summary>
public class DcLocatorLdapTests
{
    private const uint NtVersion5Ex = 0x4;
    private const uint NtVersion5ExWithIp = 0x8;
    private const uint NtVersionWithClosestSite = 0x10;

    private static readonly Guid s_guid = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef");

    private static readonly DcLocatorLdap s_ldap = new([
        new DcLocatorDomain("example.test", "EXAMPLE", s_guid, [
            ("kdc1.example.test", IPAddress.Parse("127.0.0.1")),
            ("kdc2.example.test", IPAddress.Parse("127.0.0.2")),
        ]),
    ]);

    /// <summary>Builds a ping like the Windows DC locator, (&amp;(DnsDomain=..)(Host=..)(NtVer=..)).</summary>
    private static byte[] NewPing(string domain, uint ntVersion)
    {
        byte[] ntVer = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(ntVer, ntVersion);

        AsnWriter writer = new(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(7);
            using (writer.PushSequence(new Asn1Tag(TagClass.Application, 3)))
            {
                writer.WriteOctetString([]);
                writer.WriteEnumeratedValue(SearchScope.BaseObject);
                writer.WriteEnumeratedValue(SearchScope.BaseObject);
                writer.WriteInteger(0);
                writer.WriteInteger(0);
                writer.WriteBoolean(false);
                using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    WriteEquality(writer, "DnsDomain", Encoding.UTF8.GetBytes(domain));
                    WriteEquality(writer, "Host", "CLIENT"u8.ToArray());
                    WriteEquality(writer, "NtVer", ntVer);
                }
                using (writer.PushSequence())
                {
                    writer.WriteOctetString("Netlogon"u8);
                }
            }
        }
        return writer.Encode();
    }

    private static void WriteEquality(AsnWriter writer, string attribute, byte[] value)
    {
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3)))
        {
            writer.WriteOctetString(Encoding.UTF8.GetBytes(attribute));
            writer.WriteOctetString(value);
        }
    }

    /// <summary>Reads the Netlogon value of the search result entry, null if there is none.</summary>
    private static async Task<byte[]?> ParseReply(byte[] reply)
    {
        AsnReader reader = new(reply, AsnEncodingRules.BER);
        byte[]? netlogon = null;

        AsnReader message = reader.ReadSequence();
        await Assert.That(message.TryReadInt32(out int messageId)).IsTrue();
        await Assert.That(messageId).IsEqualTo(7);
        if (message.PeekTag() == new Asn1Tag(TagClass.Application, 4, true))
        {
            AsnReader entry = message.ReadSequence(new Asn1Tag(TagClass.Application, 4));
            await Assert.That(entry.ReadOctetString().Length).IsEqualTo(0);
            AsnReader attribute = entry.ReadSequence().ReadSequence();
            await Assert.That(Encoding.UTF8.GetString(attribute.ReadOctetString())).IsEqualTo("Netlogon");
            netlogon = attribute.ReadSetOf().ReadOctetString();

            message = reader.ReadSequence();
            message.ReadInteger();
        }

        AsnReader done = message.ReadSequence(new Asn1Tag(TagClass.Application, 5));
        await Assert.That(done.ReadEnumeratedValue<SearchScope>()).IsEqualTo(SearchScope.BaseObject);
        await Assert.That(reader.HasData).IsFalse();
        return netlogon;
    }

    private static List<string> ReadNames(byte[] data, ref int offset, int count)
    {
        List<string> names = [];
        for (int i = 0; i < count; i++)
        {
            List<string> labels = [];
            while (data[offset] != 0)
            {
                labels.Add(Encoding.UTF8.GetString(data, offset + 1, data[offset]));
                offset += data[offset] + 1;
            }
            offset++;
            names.Add(string.Join('.', labels));
        }
        return names;
    }

    [Test]
    public async Task AnswersPingForRealm()
    {
        byte[] netlogon = (await ParseReply(s_ldap.Process(NewPing("EXAMPLE.TEST", NtVersion5Ex),
            IPAddress.Parse("127.0.0.2"))!))!;

        await Assert.That((int)BinaryPrimitives.ReadUInt16LittleEndian(netlogon)).IsEqualTo(23);
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(netlogon.AsSpan(4));
        // DS_KDC_FLAG, DS_LDAP_FLAG and DS_DS_FLAG are what the locator needs for a KDC.
        await Assert.That(flags & 0x38).IsEqualTo(0x38u);
        await Assert.That(new Guid(netlogon.AsSpan(8, 16))).IsEqualTo(s_guid);

        int offset = 24;
        List<string> names = ReadNames(netlogon, ref offset, 8);
        await Assert.That(names).IsEquivalentTo(new[]
        {
            "example.test", "example.test", "kdc2.example.test", "EXAMPLE", "KDC2", "",
            "Default-First-Site-Name", "Default-First-Site-Name",
        });

        // NtVersion, LmNtToken and Lm20Token end the message.
        await Assert.That(netlogon.Length - offset).IsEqualTo(8);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian(netlogon.AsSpan(offset))).IsEqualTo(5u);
    }

    [Test]
    public async Task IncludesAddressAndClosestSite()
    {
        byte[] netlogon = (await ParseReply(s_ldap.Process(
            NewPing("example.test.", NtVersion5ExWithIp | NtVersionWithClosestSite), IPAddress.Loopback)!))!;

        int offset = 24;
        List<string> names = ReadNames(netlogon, ref offset, 8);
        await Assert.That(names[2]).IsEqualTo("kdc1.example.test");

        await Assert.That((int)netlogon[offset]).IsEqualTo(16);
        await Assert.That((int)BinaryPrimitives.ReadUInt16LittleEndian(netlogon.AsSpan(offset + 1))).IsEqualTo(2);
        await Assert.That(netlogon.AsSpan(offset + 5, 4).ToArray()).IsEquivalentTo(new byte[] { 127, 0, 0, 1 });
        offset += 17;

        // An empty NextClosestSiteName.
        await Assert.That((int)netlogon[offset]).IsEqualTo(0);
        await Assert.That(netlogon.Length - offset - 1).IsEqualTo(8);
    }

    [Test]
    public async Task AnswersPingForOtherDomainWithoutEntry()
    {
        byte[]? netlogon = await ParseReply(s_ldap.Process(NewPing("other.test", NtVersion5Ex), IPAddress.Loopback)!);

        await Assert.That(netlogon).IsNull();
    }

    [Test]
    public async Task IgnoresOtherRequests()
    {
        AsnWriter writer = new(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(1);
            // An unbind request.
            writer.WriteNull(new Asn1Tag(TagClass.Application, 2));
        }

        await Assert.That(s_ldap.Process(writer.Encode(), IPAddress.Loopback)).IsNull();
        await Assert.That(s_ldap.Process(new byte[] { 0x30, 0x80 }, IPAddress.Loopback)).IsNull();
    }

    private enum SearchScope
    {
        BaseObject = 0,
    }
}
