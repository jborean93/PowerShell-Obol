using System;

namespace Obol.Kerberos;

/// <summary>The PAC_CLIENT_INFO buffer of a PAC, MS-PAC 2.7, binds the PAC to the client and its authentication
/// time.</summary>
public sealed class PacClientInfo
{
    internal PacClientInfo(DateTime clientId, string name)
    {
        ClientId = clientId;
        Name = name;
    }

    /// <summary>The local time of the initial authentication, the AuthTime of the ticket.</summary>
    public DateTime ClientId { get; }

    /// <summary>The client name as the KDC knows it.</summary>
    public string Name { get; }

    public override string ToString() => $"{Name} at {ClientId}";
}
