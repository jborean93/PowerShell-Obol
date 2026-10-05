using System;
using Kerberos.NET.Entities;
using Obol.Kerberos;

namespace Obol.Protocol;

/// <summary>A failure processing a request that is returned to the client as a KRB-ERROR.</summary>
internal sealed class KdcException : Exception
{
    public KdcException(
        ErrorCode code,
        string? text = null,
        KrbPrincipalName? sname = null,
        ReadOnlyMemory<byte>? errorData = null)
        : base(text ?? code.ToString())
    {
        Code = code;
        Text = text;
        SName = sname;
        ErrorData = errorData;
    }

    public ErrorCode Code { get; }

    /// <summary>The e-text of the error, if any.</summary>
    public string? Text { get; }

    /// <summary>The sname of the error, the krbtgt of the realm if not set.</summary>
    public KrbPrincipalName? SName { get; }

    /// <summary>The e-data of the error, if any.</summary>
    public ReadOnlyMemory<byte>? ErrorData { get; }
}
