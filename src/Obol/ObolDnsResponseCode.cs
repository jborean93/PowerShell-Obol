namespace Obol;

/// <summary>The DNS response codes (RCODE), RFC 1035 4.1.1.</summary>
public enum ObolDnsResponseCode : ushort
{
    /// <summary>The query succeeded, the name exists even if it has no record of the type asked for.</summary>
    NoError = 0,

    /// <summary>The query could not be interpreted.</summary>
    FormatError = 1,

    /// <summary>The server could not process the query.</summary>
    ServerFailure = 2,

    /// <summary>The name does not exist, also known as NXDOMAIN.</summary>
    NameError = 3,

    /// <summary>The server does not support the kind of query.</summary>
    NotImplemented = 4,

    /// <summary>The server refuses to answer, the DC locator DNS server refuses names outside of its realms.</summary>
    Refused = 5,
}
