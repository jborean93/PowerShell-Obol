using System.Linq;

namespace Obol.Kerberos;

/// <summary>AD-IF-RELEVANT, elements a service may ignore if it does not understand them, holds the PAC.</summary>
public sealed class IfRelevantAuthorizationData : AuthorizationData
{
    internal IfRelevantAuthorizationData(byte[] data, AuthorizationData[] elements)
        : base(AuthorizationDataType.IfRelevant, data)
    {
        Element = elements;
    }

    /// <summary>The elements inside.</summary>
    public AuthorizationData[] Element { get; }

    public override string ToString() => $"{Type} [{string.Join(", ", Element.Select(e => e.ToString()))}]";
}
