using System;
using System.Management.Automation;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsData.ConvertTo, "ObolSalt"
)]
[OutputType(typeof(string))]
public sealed class ConvertToObolSalt : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    [ValidateNotNullOrEmpty]
    public string Name { get; set; } = "";

    [Parameter(
        ValueFromPipelineByPropertyName = true
    )]
    [ValidateNotNullOrEmpty]
    public string? Realm { get; set; }

    [Parameter]
    public ObolSaltType SaltType { get; set; } = ObolSaltType.Default;

    protected override void BeginProcessing()
    {
        // PowerShell binding rejects undefined values but [Enum]::ToObject can still create one.
        if (!Enum.IsDefined(SaltType))
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException(
                    $"SaltType '{SaltType}' is not supported, valid values are " +
                    string.Join(", ", Enum.GetNames<ObolSaltType>())),
                "InvalidSaltType",
                ErrorCategory.InvalidArgument,
                SaltType));
        }
    }

    protected override void ProcessRecord()
    {
        string? salt = SaltType switch
        {
            ObolSaltType.ADUser => GetADUserSalt(),
            ObolSaltType.ADComputer => GetADComputerSalt(),
            _ => GetDefaultSalt(),
        };
        if (salt is not null)
        {
            WriteObject(salt);
        }
    }

    /// <summary>The RFC 4120 4. salt, the realm followed by each component, the name can include the realm.</summary>
    private string? GetDefaultSalt()
    {
        string[]? components = PrincipalCommandHelper.ParseNameWithRealm(Name, Realm, out string realm,
            out ErrorRecord? error);
        if (components is null)
        {
            WriteError(error!);
            return null;
        }

        return PrincipalStore.GetDefaultSalt(realm, components);
    }

    /// <summary>The AD salt of a user account (MS-KILE 3.1.1.2), the uppercase realm and the sAMAccountName.</summary>
    private string? GetADUserSalt()
    {
        if (Name.AsSpan().IndexOfAny('@', '\\') != -1)
        {
            WriteInvalidArgument("InvalidADUser",
                $"The AD user '{Name}' must be the sAMAccountName, such as 'user', not a UPN or DOMAIN\\user name, " +
                "set the domain with -Realm");
            return null;
        }

        return CheckADRealm() is string realm ? realm.ToUpperInvariant() + Name : null;
    }

    /// <summary>
    /// The AD salt of a computer account (MS-KILE 3.1.1.2), the uppercase realm, 'host', the lowercase computer name
    /// without '$', '.' and the lowercase realm.
    /// </summary>
    private string? GetADComputerSalt()
    {
        string computer = Name.EndsWith('$') ? Name[..^1] : Name;
        if (computer.Length == 0 || computer.AsSpan().IndexOfAny('.', '@', '\\') != -1)
        {
            WriteInvalidArgument("InvalidADComputer",
                $"The AD computer '{Name}' must be the computer name, such as 'web' or 'web$', not a DNS name, set " +
                "the domain with -Realm");
            return null;
        }

        return CheckADRealm() is string realm
            ? $"{realm.ToUpperInvariant()}host{computer.ToLowerInvariant()}.{realm.ToLowerInvariant()}"
            : null;
    }

    private string? CheckADRealm()
    {
        if (Realm is null)
        {
            WriteInvalidArgument("RealmRequired",
                $"The AD account '{Name}' needs the DNS name of its domain in -Realm");
        }
        return Realm;
    }

    private void WriteInvalidArgument(string errorId, string message)
        => WriteError(new ErrorRecord(new ArgumentException(message), errorId, ErrorCategory.InvalidArgument, Name));
}
