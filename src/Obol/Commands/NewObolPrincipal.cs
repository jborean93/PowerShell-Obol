using System;
using System.Linq;
using System.Management.Automation;
using System.Security;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.New, "ObolPrincipal",
    DefaultParameterSetName = RandomParameterSet,
    SupportsShouldProcess = true
)]
[OutputType(typeof(ObolPrincipal))]
public sealed class NewObolPrincipal : PSCmdlet
{
    // The sets follow where the keys come from, -Setting and Start-ObolKdc -Principal still check the combinations
    // when the cmdlet runs as a setting cast from a hashtable skips parameter binding.
    private const string RandomParameterSet = "Random";
    private const string PasswordParameterSet = "Password";
    private const string KeyParameterSet = "Key";
    private const string SettingParameterSet = "Setting";

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
        Mandatory = true,
        ParameterSetName = PasswordParameterSet
    )]
    [ValidateNotNull]
    public SecureString? Password { get; set; }

    [Parameter(
        ParameterSetName = RandomParameterSet
    )]
    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        ParameterSetName = KeyParameterSet
    )]
    public ObolPrincipalFlag Flag { get; set; }

    [Parameter(
        ParameterSetName = RandomParameterSet
    )]
    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [ValidateNotNull]
    public ObolEncryptionType[]? EncryptionType { get; set; }

    [Parameter(
        ParameterSetName = RandomParameterSet
    )]
    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        ParameterSetName = KeyParameterSet
    )]
    [ValidateNotNull]
    public string[]? Alias { get; set; }

    [Parameter(
        ParameterSetName = RandomParameterSet
    )]
    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        ParameterSetName = KeyParameterSet
    )]
    [ValidateRange(1, int.MaxValue)]
    public int? Rid { get; set; }

    [Parameter(
        Mandatory = true,
        ParameterSetName = KeyParameterSet
    )]
    [ValidateNotNull]
    public ObolKeytabEntry[]? Key { get; set; }

    [Parameter(
        ParameterSetName = RandomParameterSet
    )]
    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        ParameterSetName = KeyParameterSet
    )]
    [ValidateRange(0, int.MaxValue)]
    public int? Kvno { get; set; }

    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        ParameterSetName = KeyParameterSet
    )]
    [ValidateNotNull]
    public string? Salt { get; set; }

    [Parameter(
        Mandatory = true,
        ParameterSetName = SettingParameterSet
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
            Key = Key,
            Kvno = Kvno,
            Salt = Salt,
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

        error = PrincipalCommandHelper.CheckKeyParameters(
            setting.Password,
            false,
            setting.EncryptionType,
            setting.Key,
            setting.Kvno,
            setting.Salt);
        if (error is not null)
        {
            return null;
        }

        string fullName = $"{PrincipalName.Unparse(components)}@{kdc.Realm}";
        ImportedKeys? importedKeys = null;
        if (setting.Key is not null)
        {
            string[] names = [PrincipalName.Unparse(components), .. aliases?.Select(PrincipalName.Unparse) ?? []];
            importedKeys = KeytabKeySelector.Select(
                cmdlet,
                setting.Key,
                kdc.Store,
                names,
                fullName,
                setting.Kvno,
                out error);
            if (importedKeys is null)
            {
                return null;
            }
        }

        if (!cmdlet.ShouldProcess(fullName, "Create principal"))
        {
            return null;
        }

        try
        {
            return kdc.Store.Create(components, setting.Password, setting.Flag, etypes, aliases,
                (uint?)setting.Rid, setting.Salt, importedKeys, setting.Kvno);
        }
        catch (PrincipalStoreException e)
        {
            error = PrincipalCommandHelper.StoreError(e, fullName);
            return null;
        }
    }
}
