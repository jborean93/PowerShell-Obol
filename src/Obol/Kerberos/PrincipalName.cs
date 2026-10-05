namespace Obol.Kerberos;

/// <summary>A principal name in a Kerberos message with the realm it was sent with.</summary>
public sealed class PrincipalName
{
    internal PrincipalName(PrincipalNameType nameType, string[] components, string realm)
    {
        NameType = nameType;
        Component = components;
        Name = Protocol.PrincipalName.Unparse(components);
        Realm = realm;
    }

    /// <summary>
    /// The name type, such as <c>Principal</c> for a user or <c>ServiceInstance</c> for a service. A type without a
    /// name is shown as its number.
    /// </summary>
    public PrincipalNameType NameType { get; }

    /// <summary>The name components, such as <c>HTTP</c> and <c>web.example.test</c>.</summary>
    public string[] Component { get; }

    /// <summary>The name without the realm, with '/', '@' and '\' in a component escaped with '\'.</summary>
    public string Name { get; }

    /// <summary>The realm the name was sent with, the realm field of the structure holding the name.</summary>
    public string Realm { get; }

    /// <summary>The name with the realm, such as <c>HTTP/web.example.test@EXAMPLE.TEST</c>.</summary>
    public string FullName => $"{Name}@{Realm}";

    public override string ToString() => FullName;
}
