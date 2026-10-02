using System.Linq;
using System.Threading;
using Obol.Protocol;

namespace Obol;

/// <summary>A user or service principal in the realm of an <see cref="ObolKdc"/>.</summary>
/// <remarks>The object reflects later changes made with Set-ObolPrincipal.</remarks>
public sealed class ObolPrincipal
{
    private PrincipalState _state;

    internal ObolPrincipal(
        PrincipalStore store,
        string[] components,
        PrincipalState state,
        uint rid,
        string sid)
    {
        Store = store;
        Components = components;
        Name = PrincipalName.Unparse(components);
        _state = state;
        Rid = rid;
        Sid = sid;
    }

    /// <summary>
    /// The principal name without the realm, such as <c>user</c> or <c>HTTP/web.example.test</c>, with '/', '@' and '\'
    /// in a component escaped with '\'.
    /// </summary>
    public string Name { get; }

    /// <summary>The realm of the principal.</summary>
    public string Realm => Store.Realm;

    /// <summary>The principal name with the realm, such as <c>user@EXAMPLE.TEST</c>.</summary>
    public string FullName => $"{Name}@{Realm}";

    /// <summary>Other names the principal can be found by, such as further service principal names.</summary>
    public string[] Alias => [.. State.Aliases];

    /// <summary>The version number of the principal's keys, it increases each time the keys change.</summary>
    public int Kvno => State.Kvno;

    /// <summary>The encryption types the principal has keys for, in order of preference.</summary>
    public ObolEncryptionType[] EncryptionType => State.EncryptionTypes;

    /// <summary>
    /// The salt sent to clients to derive the principal's keys from its password, not set for random keys.
    /// </summary>
    public string? Salt => State.Keys.FirstOrDefault()?.Salt;

    /// <summary>The options turned on for the principal, such as not requiring pre-authentication.</summary>
    public ObolPrincipalFlag Flag => State.Flags;

    /// <summary>The security identifier of the principal used in the PAC.</summary>
    public string Sid { get; }

    /// <summary>The store the principal belongs to.</summary>
    internal PrincipalStore Store { get; }

    /// <summary>The name components, such as <c>HTTP</c> and <c>web.example.test</c>.</summary>
    internal string[] Components { get; }

    /// <summary>The relative identifier of the principal in the KDC's domain SID.</summary>
    internal uint Rid { get; }

    /// <summary>The current values of the principal.</summary>
    internal PrincipalState State
    {
        get => Volatile.Read(ref _state);
        set => Volatile.Write(ref _state, value);
    }

    /// <summary>Whether the principal is the KDC's own krbtgt principal.</summary>
    internal bool IsKrbtgt => Components.Length == 2 && Components[0] == "krbtgt" && Components[1] == Realm;

    public override string ToString() => FullName;
}
