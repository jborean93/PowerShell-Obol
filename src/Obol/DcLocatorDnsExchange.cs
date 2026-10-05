using System.Collections.Generic;

namespace Obol;

/// <summary>A DNS query to the DC locator DNS server and the reply sent.</summary>
internal sealed class DcLocatorDnsExchange : DcLocatorExchange
{
    /// <summary>The ID of the query, null if it was too short to have a header.</summary>
    public ushort? Id { get; set; }

    /// <summary>The name in the question, null if it could not be read.</summary>
    public string? Name { get; set; }

    /// <summary>The type in the question, null if it could not be read.</summary>
    public ObolDnsRecordType? Type { get; set; }

    /// <summary>The response code of the reply, null if there was no reply.</summary>
    public ObolDnsResponseCode? ResponseCode { get; set; }

    /// <summary>The records in the answer section of the reply.</summary>
    public List<ObolDnsRecord> Answers { get; } = [];

    /// <summary>The records in the additional section of the reply.</summary>
    public List<ObolDnsRecord> Additional { get; } = [];
}
