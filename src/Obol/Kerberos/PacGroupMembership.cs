namespace Obol.Kerberos;

/// <summary>A GROUP_MEMBERSHIP of the PAC logon information, a group in the user's domain, MS-PAC 2.2.2.</summary>
public sealed class PacGroupMembership
{
    internal PacGroupMembership(uint relativeId, PacGroupAttribute attribute)
    {
        RelativeId = relativeId;
        Attribute = attribute;
    }

    /// <summary>The RID of the group in the domain of the logon information.</summary>
    public uint RelativeId { get; }

    /// <summary>The attributes of the membership.</summary>
    public PacGroupAttribute Attribute { get; }

    public override string ToString() => $"{RelativeId} ({Attribute})";
}
