using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Obol;

/// <summary>
/// Answers the DNS queries the Windows DC locator makes for the realms of a DC locator SSPI environment.
/// </summary>
/// <remarks>
/// The locator looks up <c>_kerberos._tcp.dc._msdcs.&lt;realm&gt;</c>, or a site specific form of it, and then the
/// address of the host in the SRV record. Any SRV query for a <c>_kerberos</c> or <c>_ldap</c> name in the realm is
/// answered with every KDC of the realm, with the address records of the KDCs in the additional section. The host name
/// of a KDC resolves to its address, the realm itself has no records and every other name in the realm does not
/// exist. Names outside of the realms are refused, the NRPT rule only sends the realm names here.
/// </remarks>
internal sealed class DcLocatorDns
{
    private const ushort TypeA = 1;
    private const ushort TypeAaaa = 28;
    private const ushort TypeSrv = 33;
    private const ushort ClassIn = 1;

    private const int HeaderLength = 12;
    private const ushort FlagResponse = 0x8000;
    private const ushort FlagAuthoritative = 0x0400;
    private const ushort FlagRecursionDesired = 0x0100;
    private const ushort OpcodeMask = 0x7800;

    private const ushort RcodeFormatError = 1;
    private const ushort RcodeNameError = 3;
    private const ushort RcodeNotImplemented = 4;
    private const ushort RcodeRefused = 5;

    /// <summary>The TTL of the records, the DNS client cache is flushed when the environment is entered and exited.
    /// </summary>
    private const int Ttl = 60;

    /// <summary>The port every record of the Windows KDC and LDAP ping uses, the locator ignores any other.</summary>
    private const ushort KdcPort = 88;
    private const ushort LdapPort = 389;

    private readonly IReadOnlyList<DcLocatorDomain> _domains;

    public DcLocatorDns(IReadOnlyList<DcLocatorDomain> domains)
    {
        _domains = domains;
    }

    /// <summary>Builds the reply to a DNS query.</summary>
    /// <returns>The reply, or null if the request is too malformed to reply to.</returns>
    public byte[]? Process(ReadOnlySpan<byte> request)
    {
        DcLocatorDnsExchange exchange = new() { RequestBytes = request.ToArray() };
        Process(exchange);
        return exchange.ReplyBytes;
    }

    /// <summary>
    /// Builds the reply to the query in <see cref="DcLocatorExchange.RequestBytes"/> and records what was asked and
    /// answered. <see cref="DcLocatorExchange.ReplyBytes"/> is left null if the request is too malformed to reply to.
    /// </summary>
    public void Process(DcLocatorDnsExchange exchange)
    {
        ReadOnlySpan<byte> request = exchange.RequestBytes;
        if (request.Length < HeaderLength)
        {
            return;
        }

        ushort id = BinaryPrimitives.ReadUInt16BigEndian(request);
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(request[2..]);
        ushort questions = BinaryPrimitives.ReadUInt16BigEndian(request[4..]);
        exchange.Id = id;
        if ((flags & FlagResponse) != 0)
        {
            return;
        }

        if ((flags & OpcodeMask) != 0)
        {
            SetReply(exchange, BuildError(id, flags, RcodeNotImplemented), RcodeNotImplemented);
            return;
        }
        if (questions != 1 || !TryReadQuestion(request, out string name, out ushort type, out ushort qclass,
            out int questionEnd))
        {
            SetReply(exchange, BuildError(id, flags, RcodeFormatError), RcodeFormatError);
            return;
        }
        exchange.Name = name;
        exchange.Type = (ObolDnsRecordType)type;

        ReadOnlySpan<byte> question = request[HeaderLength..questionEnd];
        DcLocatorDomain? domain = FindDomain(name);
        if (domain is null || qclass != ClassIn)
        {
            SetReply(exchange, BuildReply(id, flags, RcodeRefused, question, [], []), RcodeRefused);
            return;
        }

        List<Record> answers = [];
        List<Record> additional = [];
        bool exists = Answer(domain, name, type, answers, additional);
        ushort rcode = exists ? (ushort)0 : RcodeNameError;
        SetReply(exchange, BuildReply(id, flags, rcode, question, answers, additional), rcode);
        exchange.Answers.AddRange(answers.Select(r => r.ToObol(name)));
        exchange.Additional.AddRange(additional.Select(r => r.ToObol(name)));
    }

    private static void SetReply(DcLocatorDnsExchange exchange, byte[] reply, ushort rcode)
    {
        exchange.ReplyBytes = reply;
        exchange.ResponseCode = (ObolDnsResponseCode)rcode;
    }

    /// <summary>Finds the answers for a name in a realm.</summary>
    /// <returns>False if the name does not exist.</returns>
    private static bool Answer(
        DcLocatorDomain domain,
        string name,
        ushort type,
        List<Record> answers,
        List<Record> additional)
    {
        if (name.Equals(domain.DnsName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        string service = name.Split('.')[0];
        ushort port = service.Equals("_kerberos", StringComparison.OrdinalIgnoreCase)
            ? KdcPort
            : service.Equals("_ldap", StringComparison.OrdinalIgnoreCase) ? LdapPort : (ushort)0;
        if (port != 0)
        {
            if (type == TypeSrv)
            {
                foreach ((string host, IPAddress address) in domain.Kdcs)
                {
                    answers.Add(Record.Srv(port, host));
                    additional.Add(Record.Address(host, address));
                }
            }
            return true;
        }

        bool found = false;
        foreach ((string host, IPAddress address) in domain.Kdcs)
        {
            if (!host.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            found = true;

            // A query for the other address family has no answer, the name still exists.
            ushort addressType = address.AddressFamily == AddressFamily.InterNetworkV6 ? TypeAaaa : TypeA;
            if (type == addressType)
            {
                answers.Add(Record.Address(null, address));
            }
        }
        return found;
    }

    private DcLocatorDomain? FindDomain(string name)
    {
        foreach (DcLocatorDomain domain in _domains)
        {
            if (name.Equals(domain.DnsName, StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith($".{domain.DnsName}", StringComparison.OrdinalIgnoreCase))
            {
                return domain;
            }
        }
        return null;
    }

    /// <summary>Reads the question, the name must not be compressed as nothing comes before it.</summary>
    private static bool TryReadQuestion(
        ReadOnlySpan<byte> request,
        out string name,
        out ushort type,
        out ushort qclass,
        out int end)
    {
        name = "";
        type = qclass = 0;
        end = 0;

        StringBuilder sb = new();
        int offset = HeaderLength;
        while (true)
        {
            if (offset >= request.Length)
            {
                return false;
            }
            int length = request[offset++];
            if (length == 0)
            {
                break;
            }
            // 0xC0 is a compression pointer, 0x40 and 0x80 are reserved.
            if (length > 63 || offset + length > request.Length)
            {
                return false;
            }
            if (sb.Length > 0)
            {
                sb.Append('.');
            }
            sb.Append(Encoding.ASCII.GetString(request.Slice(offset, length)));
            offset += length;
        }

        if (offset + 4 > request.Length)
        {
            return false;
        }
        name = sb.ToString();
        type = BinaryPrimitives.ReadUInt16BigEndian(request[offset..]);
        qclass = BinaryPrimitives.ReadUInt16BigEndian(request[(offset + 2)..]);
        end = offset + 4;
        return true;
    }

    private static byte[] BuildError(ushort id, ushort requestFlags, ushort rcode)
        => BuildReply(id, requestFlags, rcode, [], [], []);

    private static byte[] BuildReply(
        ushort id,
        ushort requestFlags,
        ushort rcode,
        ReadOnlySpan<byte> question,
        List<Record> answers,
        List<Record> additional)
    {
        List<byte> reply = new(512);
        ushort flags = (ushort)(FlagResponse | FlagAuthoritative | (requestFlags & FlagRecursionDesired) | rcode);
        WriteUInt16(reply, id);
        WriteUInt16(reply, flags);
        WriteUInt16(reply, (ushort)(question.IsEmpty ? 0 : 1));
        WriteUInt16(reply, (ushort)answers.Count);
        WriteUInt16(reply, 0);
        WriteUInt16(reply, (ushort)additional.Count);
        reply.AddRange(question);

        foreach (Record record in answers)
        {
            record.Write(reply);
        }
        foreach (Record record in additional)
        {
            record.Write(reply);
        }
        return [.. reply];
    }

    private static void WriteUInt16(List<byte> buffer, ushort value)
    {
        buffer.Add((byte)(value >> 8));
        buffer.Add((byte)value);
    }

    private static void WriteName(List<byte> buffer, string name)
    {
        foreach (string label in name.Split('.'))
        {
            buffer.Add((byte)label.Length);
            buffer.AddRange(Encoding.ASCII.GetBytes(label));
        }
        buffer.Add(0);
    }

    /// <summary>A resource record, the owner is the question name when <see cref="Owner"/> is null.</summary>
    /// <remarks>The address, port and target are the value in the data, kept for <see cref="ToObol"/>.</remarks>
    private sealed record Record(string? Owner, ushort Type, byte[] Data, IPAddress? IPAddress = null,
        ushort? Port = null, string? Target = null)
    {
        /// <summary>A pointer to the question name, right after the header.</summary>
        private const ushort QuestionNamePointer = 0xC000 | HeaderLength;

        public static Record Address(string? owner, IPAddress address)
            => new(owner, address.AddressFamily == AddressFamily.InterNetworkV6 ? TypeAaaa : TypeA,
                address.GetAddressBytes(), IPAddress: address);

        public static Record Srv(ushort port, string target)
        {
            List<byte> data = [];
            WriteUInt16(data, 0);
            WriteUInt16(data, 100);
            WriteUInt16(data, port);
            WriteName(data, target);
            return new(null, TypeSrv, [.. data], Port: port, Target: target);
        }

        /// <summary>The public view of the record, the owner is <paramref name="questionName"/> if not set.</summary>
        public ObolDnsRecord ToObol(string questionName)
            => new(Owner ?? questionName, (ObolDnsRecordType)Type, Ttl, IPAddress, Port, Target);

        public void Write(List<byte> buffer)
        {
            if (Owner is null)
            {
                WriteUInt16(buffer, QuestionNamePointer);
            }
            else
            {
                WriteName(buffer, Owner);
            }
            WriteUInt16(buffer, Type);
            WriteUInt16(buffer, ClassIn);
            WriteUInt16(buffer, Ttl >> 16);
            WriteUInt16(buffer, Ttl & 0xFFFF);
            WriteUInt16(buffer, (ushort)Data.Length);
            buffer.AddRange(Data);
        }
    }
}
