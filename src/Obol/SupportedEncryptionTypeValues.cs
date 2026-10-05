using System.Linq;
using System.Management.Automation;
using Obol.Protocol;

namespace Obol;

/// <summary>
/// The <c>ValidateSet</c> of the <c>-EncryptionType</c> parameters: the <see cref="Kerberos.EncryptionType"/> values
/// a principal can have keys for, so the other registered types are rejected at binding and tab completion only
/// offers the supported ones.
/// </summary>
public sealed class SupportedEncryptionTypeValues : IValidateSetValuesGenerator
{
    public string[] GetValidValues() => [.. PrincipalStore.SupportedEncryptionTypes.Select(t => t.ToString())];
}
