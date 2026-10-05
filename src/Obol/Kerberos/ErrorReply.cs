using System;

namespace Obol.Kerberos;

/// <summary>A KRB-ERROR of RFC 4120 5.9.1, the KDC's reply to a request it did not answer with a ticket.</summary>
public sealed class ErrorReply : Message
{
    internal ErrorReply(byte[] bytes) : base(MessageType.Error, bytes) { }

    /// <summary>The pvno, always 5.</summary>
    public int ProtocolVersion { get; internal init; }

    /// <summary>The ctime and cusec, the client's time from the request, if sent.</summary>
    public DateTime? ClientTime { get; internal init; }

    /// <summary>The stime and susec, the local time on the KDC.</summary>
    public DateTime ServerTime { get; internal init; }

    /// <summary>The error-code.</summary>
    public ErrorCode ErrorCode { get; internal init; }

    /// <summary>The cname and crealm, if sent.</summary>
    public PrincipalName? ClientName { get; internal init; }

    /// <summary>The sname and realm, the krbtgt of the realm when the request named no service.</summary>
    public PrincipalName ServiceName { get; internal init; } = null!;

    /// <summary>The e-text, the reason for the error, if sent.</summary>
    public string? ErrorText { get; internal init; }

    /// <summary>The e-data, if sent.</summary>
    public byte[]? ErrorData { get; internal init; }

    /// <summary>
    /// The e-data decoded as METHOD-DATA, the pre-authentication the KDC accepts for PreAuthRequired, null if there
    /// is no e-data or it is not METHOD-DATA.
    /// </summary>
    public PreAuthData[]? MethodData { get; internal init; }

    public override string ToString() => ErrorText is null ? ErrorCode.ToString() : $"{ErrorCode}: {ErrorText}";
}
