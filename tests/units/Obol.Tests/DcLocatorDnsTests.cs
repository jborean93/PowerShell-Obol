using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Obol.Tests;

/// <summary>The DNS replies the DC locator stub sends.</summary>
public class DcLocatorDnsTests
{
    private const ushort TypeA = 1;
    private const ushort TypeAaaa = 28;
    private const ushort TypeSrv = 33;

    private static readonly DcLocatorDns s_dns = new([
        new DcLocatorDomain("example.test", "EXAMPLE", Guid.Empty, [
            ("kdc1.example.test", IPAddress.Parse("127.0.0.1")),
            ("kdc2.example.test", IPAddress.IPv6Loopback),
        ]),
    ]);

    internal static byte[] NewQuery(string name, ushort type, ushort flags = 0x0100, ushort questions = 1)
    {
        List<byte> query = [0x12, 0x34, (byte)(flags >> 8), (byte)flags, 0, (byte)questions, 0, 0, 0, 0, 0, 0];
        foreach (string label in name.Split('.'))
        {
            query.Add((byte)label.Length);
            query.AddRange(Encoding.ASCII.GetBytes(label));
        }
        query.AddRange([0, (byte)(type >> 8), (byte)type, 0, 1]);
        return [.. query];
    }

    private sealed record Reply(ushort Id, ushort Flags, int Rcode, List<(ushort Type, byte[] Data)> Answers,
        List<(string Name, ushort Type, byte[] Data)> Additional);

    private static Reply Parse(byte[] reply)
    {
        ReadOnlySpan<byte> span = reply;
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(span[2..]);
        int questions = BinaryPrimitives.ReadUInt16BigEndian(span[4..]);
        int answers = BinaryPrimitives.ReadUInt16BigEndian(span[6..]);
        int additional = BinaryPrimitives.ReadUInt16BigEndian(span[10..]);

        int offset = 12;
        for (int i = 0; i < questions; i++)
        {
            ReadName(span, ref offset);
            offset += 4;
        }

        List<(ushort, byte[])> answerRecords = [];
        for (int i = 0; i < answers; i++)
        {
            (_, ushort type, byte[] data) = ReadRecord(span, ref offset);
            answerRecords.Add((type, data));
        }
        List<(string, ushort, byte[])> additionalRecords = [];
        for (int i = 0; i < additional; i++)
        {
            additionalRecords.Add(ReadRecord(span, ref offset));
        }

        return new(BinaryPrimitives.ReadUInt16BigEndian(span), flags, flags & 0xF, answerRecords, additionalRecords);
    }

    private static (string, ushort, byte[]) ReadRecord(ReadOnlySpan<byte> span, ref int offset)
    {
        string name = ReadName(span, ref offset);
        ushort type = BinaryPrimitives.ReadUInt16BigEndian(span[offset..]);
        int length = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 8)..]);
        offset += 10;
        byte[] data = span.Slice(offset, length).ToArray();
        offset += length;
        return (name, type, data);
    }

    private static string ReadName(ReadOnlySpan<byte> span, ref int offset)
    {
        if ((span[offset] & 0xC0) == 0xC0)
        {
            int pointer = BinaryPrimitives.ReadUInt16BigEndian(span[offset..]) & 0x3FFF;
            offset += 2;
            return ReadName(span, ref pointer);
        }

        List<string> labels = [];
        while (span[offset] != 0)
        {
            int length = span[offset];
            labels.Add(Encoding.ASCII.GetString(span.Slice(offset + 1, length)));
            offset += length + 1;
        }
        offset++;
        return string.Join('.', labels);
    }

    [Test]
    [Arguments("_kerberos._tcp.dc._msdcs.example.test", 88)]
    [Arguments("_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.EXAMPLE.TEST", 88)]
    [Arguments("_kerberos._udp.example.test", 88)]
    [Arguments("_ldap._tcp.dc._msdcs.example.test", 389)]
    public async Task AnswersSrvWithEveryKdc(string name, int port)
    {
        Reply reply = Parse(s_dns.Process(NewQuery(name, TypeSrv))!);

        await Assert.That(reply.Id).IsEqualTo((ushort)0x1234);
        // QR, AA and RD copied from the query.
        await Assert.That(reply.Flags & 0xFFF0).IsEqualTo(0x8500);
        await Assert.That(reply.Rcode).IsEqualTo(0);
        await Assert.That(reply.Answers.Count).IsEqualTo(2);
        await Assert.That(reply.Answers[0].Type).IsEqualTo(TypeSrv);
        await Assert.That((int)BinaryPrimitives.ReadUInt16BigEndian(reply.Answers[0].Data.AsSpan(4))).IsEqualTo(port);
        await Assert.That(reply.Additional.Count).IsEqualTo(2);
        await Assert.That(reply.Additional[0].Name).IsEqualTo("kdc1.example.test");
        await Assert.That(reply.Additional[0].Type).IsEqualTo(TypeA);
        await Assert.That(reply.Additional[0].Data).IsEquivalentTo(new byte[] { 127, 0, 0, 1 });
        await Assert.That(reply.Additional[1].Type).IsEqualTo(TypeAaaa);
    }

    [Test]
    public async Task AnswersKdcAddress()
    {
        Reply reply = Parse(s_dns.Process(NewQuery("KDC1.example.test", TypeA))!);

        await Assert.That(reply.Rcode).IsEqualTo(0);
        await Assert.That(reply.Answers.Count).IsEqualTo(1);
        await Assert.That(reply.Answers[0].Data).IsEquivalentTo(new byte[] { 127, 0, 0, 1 });
    }

    [Test]
    [Arguments("kdc1.example.test", TypeAaaa)]
    [Arguments("kdc2.example.test", TypeA)]
    [Arguments("example.test", TypeA)]
    [Arguments("_kerberos._tcp.example.test", TypeA)]
    public async Task AnswersExistingNameWithoutRecords(string name, ushort type)
    {
        Reply reply = Parse(s_dns.Process(NewQuery(name, type))!);

        await Assert.That(reply.Rcode).IsEqualTo(0);
        await Assert.That(reply.Answers.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("web.example.test")]
    [Arguments("_kpasswd._tcp.example.test")]
    public async Task AnswersNameErrorInRealm(string name)
    {
        Reply reply = Parse(s_dns.Process(NewQuery(name, TypeA))!);

        await Assert.That(reply.Rcode).IsEqualTo(3);
    }

    [Test]
    [Arguments("other.test")]
    [Arguments("notexample.test")]
    public async Task RefusesOtherNames(string name)
    {
        Reply reply = Parse(s_dns.Process(NewQuery(name, TypeA))!);

        await Assert.That(reply.Rcode).IsEqualTo(5);
    }

    [Test]
    public async Task RejectsOtherOpcode()
    {
        // Opcode 2, a server status request.
        Reply reply = Parse(s_dns.Process(NewQuery("example.test", TypeA, flags: 0x1000))!);

        await Assert.That(reply.Rcode).IsEqualTo(4);
    }

    [Test]
    public async Task RejectsSeveralQuestions()
    {
        Reply reply = Parse(s_dns.Process(NewQuery("example.test", TypeA, questions: 2))!);

        await Assert.That(reply.Rcode).IsEqualTo(1);
    }

    [Test]
    public async Task IgnoresReplyAndShortMessage()
    {
        await Assert.That(s_dns.Process(NewQuery("example.test", TypeA, flags: 0x8000))).IsNull();
        await Assert.That(s_dns.Process(new byte[4])).IsNull();
    }
}
