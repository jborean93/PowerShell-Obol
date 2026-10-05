namespace Obol.Kerberos;

/// <summary>A KERB_SID_AND_ATTRIBUTES of the PAC logon information, a SID outside the user's domain, MS-PAC 2.2.1.
/// </summary>
public sealed class PacSidAttributes
{
    internal PacSidAttributes(string sid, PacGroupAttribute attribute)
    {
        Sid = sid;
        Attribute = attribute;
    }

    /// <summary>The SID.</summary>
    public string Sid { get; }

    /// <summary>The attributes of the membership.</summary>
    public PacGroupAttribute Attribute { get; }

    public override string ToString() => $"{Sid} ({Attribute})";
}
