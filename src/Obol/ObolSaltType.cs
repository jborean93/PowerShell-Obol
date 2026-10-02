namespace Obol;

/// <summary>How the salt that keys are derived from a password with is built.</summary>
public enum ObolSaltType
{
    /// <summary>The RFC 4120 salt used by MIT, Heimdal and Obol, the realm followed by each name component.</summary>
    Default = 0,

    /// <summary>The salt of an AD user or service account, the uppercase realm and the sAMAccountName.</summary>
    ADUser = 1,

    /// <summary>
    /// The salt of an AD computer account, the uppercase realm, 'host', the lowercase computer name without '$', '.'
    /// and the lowercase realm.
    /// </summary>
    ADComputer = 2,
}
