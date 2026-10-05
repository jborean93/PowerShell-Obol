using System.Net;

namespace Obol;

/// <summary>A resource record in the reply of an <see cref="ObolDnsEvent"/>.</summary>
public sealed class ObolDnsRecord
{
    internal ObolDnsRecord(string name, ObolDnsRecordType type, int ttl, IPAddress? address, int? port,
        string? target)
    {
        Name = name;
        Type = type;
        Ttl = ttl;
        Address = address;
        Port = port;
        Target = target;
    }

    /// <summary>The name the record is for.</summary>
    public string Name { get; }

    /// <summary>The type of the record, <c>A</c>, <c>Aaaa</c> or <c>Srv</c>.</summary>
    public ObolDnsRecordType Type { get; }

    /// <summary>How many seconds the client may cache the record.</summary>
    public int Ttl { get; }

    /// <summary>The address of an <c>A</c> or <c>Aaaa</c> record, otherwise null.</summary>
    public IPAddress? Address { get; }

    /// <summary>The port of an <c>Srv</c> record, otherwise null.</summary>
    public int? Port { get; }

    /// <summary>The host name of an <c>Srv</c> record, otherwise null.</summary>
    public string? Target { get; }

    /// <summary>The value of the record, the address or the target and port such as kdc1.example.test:88.</summary>
    internal string Value => Address?.ToString() ?? $"{Target}:{Port}";

    public override string ToString() => $"{Name} {Type.ToString().ToUpperInvariant()} {Value}";
}
