using System;

namespace Obol.Kerberos;

/// <summary>A LastReq entry of RFC 4120 5.4.2, a time the KDC reports to the client.</summary>
public sealed class LastRequest
{
    internal LastRequest(int type, DateTime value)
    {
        Type = type;
        Value = value;
    }

    /// <summary>The lr-type, 0 for no information, the others are in RFC 4120 5.4.2.</summary>
    public int Type { get; }

    /// <summary>The local time.</summary>
    public DateTime Value { get; }

    public override string ToString() => $"{Type}: {Value}";
}
