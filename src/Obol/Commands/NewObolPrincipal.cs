using System;
using System.Management.Automation;
using System.Security;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.New, "ObolPrincipal",
    DefaultParameterSetName = "Parameter",
    SupportsShouldProcess = true
)]
[OutputType(typeof(ObolPrincipal))]
public sealed class NewObolPrincipal : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        ValueFromPipeline = true
    )]
    [ValidateNotNull]
    public ObolKdc? Kdc { get; set; }

    [Parameter(
        Mandatory = true,
        Position = 0
    )]
    [ValidateNotNullOrEmpty]
    public string Name { get; set; } = "";

    [Parameter(
        ParameterSetName = "Parameter"
    )]
    [ValidateNotNull]
    public SecureString? Password { get; set; }

    [Parameter(
        ParameterSetName = "Parameter"
    )]
    public ObolPrincipalFlag Flag { get; set; }

    [Parameter(
        ParameterSetName = "Parameter"
    )]
    [ValidateNotNull]
    public ObolEncryptionType[]? EncryptionType { get; set; }

    [Parameter(
        ParameterSetName = "Parameter"
    )]
    [ValidateNotNull]
    public string[]? Alias { get; set; }

    [Parameter(
        ParameterSetName = "Parameter"
    )]
    [ValidateRange(1, int.MaxValue)]
    public int? Rid { get; set; }

    [Parameter(
        Mandatory = true,
        ParameterSetName = "Setting"
    )]
    [ValidateNotNull]
    public ObolPrincipalSetting? Setting { get; set; }

    protected override void ProcessRecord()
    {
        ObolPrincipalSetting setting = Setting ?? new ObolPrincipalSetting
        {
            Password = Password,
            Flag = Flag,
            EncryptionType = EncryptionType,
            Alias = Alias,
            Rid = Rid,
        };

        ObolPrincipal? principal = Create(this, Kdc!, Name, setting, out ErrorRecord? error);
        if (error is not null)
        {
            WriteError(error);
        }
        else if (principal is not null)
        {
            WriteObject(principal);
        }
    }

    /// <summary>Validates the settings and creates the principal, shared with Start-ObolKdc -Principal.</summary>
    /// <remarks>
    /// The settings can come from a hashtable cast without the parameter validation so every value is checked here.
    /// </remarks>
    /// <returns>The principal, or null if it was not created because of an error or ShouldProcess.</returns>
    internal static ObolPrincipal? Create(
        Cmdlet cmdlet,
        ObolKdc kdc,
        string name,
        ObolPrincipalSetting setting,
        out ErrorRecord? error)
    {
        string[]? components = PrincipalCommandHelper.ParseName(name, kdc.Realm, out error);
        if (components is null)
        {
            return null;
        }

        string[][]? aliases = PrincipalCommandHelper.ParseAliases(setting.Alias, kdc.Realm, out error);
        if (error is not null)
        {
            return null;
        }

        error = PrincipalCommandHelper.CheckFlags(setting.Flag);
        if (error is not null)
        {
            return null;
        }

        ObolEncryptionType[]? etypes = PrincipalCommandHelper.CheckEncryptionTypes(setting.EncryptionType, out error);
        if (error is not null)
        {
            return null;
        }

        if (setting.Rid <= 0)
        {
            error = new ErrorRecord(
                new ArgumentException($"The RID must be greater than 0, got {setting.Rid}"),
                "InvalidRid",
                ErrorCategory.InvalidArgument,
                setting.Rid);
            return null;
        }

        if (setting.Password is not null && setting.Password.Length == 0)
        {
            error = new ErrorRecord(
                new ArgumentException("The password must not be empty"),
                "EmptyPassword",
                ErrorCategory.InvalidArgument,
                name);
            return null;
        }

        string fullName = $"{PrincipalName.Unparse(components)}@{kdc.Realm}";
        if (!cmdlet.ShouldProcess(fullName, "Create principal"))
        {
            return null;
        }

        try
        {
            return kdc.Store.Create(components, setting.Password, setting.Flag, etypes, aliases,
                (uint?)setting.Rid);
        }
        catch (PrincipalStoreException e)
        {
            error = PrincipalCommandHelper.StoreError(e, fullName);
            return null;
        }
    }
}
