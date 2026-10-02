using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Security;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.Set, "ObolPrincipal",
    DefaultParameterSetName = PrincipalParameterSet,
    SupportsShouldProcess = true
)]
[OutputType(typeof(ObolPrincipal))]
public sealed class SetObolPrincipal : PSCmdlet
{
    private const string PrincipalParameterSet = "Principal";
    private const string NameParameterSet = "Name";

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ParameterSetName = PrincipalParameterSet
    )]
    [ValidateNotNull]
    public ObolPrincipal[] Principal { get; set; } = [];

    [Parameter(
        Mandatory = true,
        ValueFromPipeline = true,
        ParameterSetName = NameParameterSet
    )]
    [ValidateNotNull]
    public ObolKdc? Kdc { get; set; }

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = NameParameterSet
    )]
    [ValidateNotNullOrEmpty]
    public string[] Name { get; set; } = [];

    [Parameter]
    [ValidateNotNull]
    public SecureString? Password { get; set; }

    [Parameter]
    public SwitchParameter NewRandomKey { get; set; }

    [Parameter]
    [ValidateNotNull]
    public ObolEncryptionType[]? EncryptionType { get; set; }

    [Parameter]
    public ObolPrincipalFlag Flag { get; set; }

    [Parameter]
    [AllowEmptyCollection]
    [ValidateNotNull]
    public string[]? Alias { get; set; }

    [Parameter]
    [ValidateNotNull]
    public ObolKeytabEntry[]? Key { get; set; }

    [Parameter]
    [ValidateRange(0, int.MaxValue)]
    public int? Kvno { get; set; }

    [Parameter]
    [ValidateNotNull]
    public string? Salt { get; set; }

    [Parameter]
    public SwitchParameter PassThru { get; set; }

    protected override void BeginProcessing()
    {
        if (PrincipalCommandHelper.CheckKeyParameters(Password, NewRandomKey, EncryptionType, Key, Kvno, Salt) is
            ErrorRecord error)
        {
            ThrowTerminatingError(error);
        }
    }

    protected override void ProcessRecord()
    {
        ObolEncryptionType[]? etypes = PrincipalCommandHelper.CheckEncryptionTypes(
            EncryptionType,
            out ErrorRecord? error);
        if (error is not null)
        {
            WriteError(error);
            return;
        }

        // The flags replace the existing flags, like the aliases, only when set.
        ObolPrincipalFlag? flags = null;
        if (MyInvocation.BoundParameters.ContainsKey(nameof(Flag)))
        {
            error = PrincipalCommandHelper.CheckFlags(Flag);
            if (error is not null)
            {
                WriteError(error);
                return;
            }
            flags = Flag;
        }

        IEnumerable<ObolPrincipal> principals = ParameterSetName == NameParameterSet
            ? PrincipalCommandHelper.FindByName(this, Kdc!, Name)
            : Principal;
        foreach (ObolPrincipal principal in principals)
        {
            string[][]? aliases = PrincipalCommandHelper.ParseAliases(Alias, principal.Realm, out error);
            if (error is not null)
            {
                WriteError(error);
                continue;
            }

            // The keys are taken from the entries for the principal name or the aliases it has after the change.
            ImportedKeys? importedKeys = null;
            if (Key is not null)
            {
                string[] names = [
                    principal.Name,
                    .. aliases?.Select(PrincipalName.Unparse) ?? principal.Alias,
                ];
                importedKeys = KeytabKeySelector.Select(
                    this,
                    Key,
                    principal.Store,
                    names,
                    principal.FullName,
                    Kvno,
                    out error);
                if (importedKeys is null)
                {
                    WriteError(error!);
                    continue;
                }
            }

            if (!ShouldProcess(principal.FullName, "Set principal"))
            {
                continue;
            }

            try
            {
                principal.Store.Update(principal, Password, NewRandomKey, etypes, flags, aliases, Salt, importedKeys,
                    Kvno);
            }
            catch (PrincipalStoreException e)
            {
                WriteError(PrincipalCommandHelper.StoreError(e, principal));
                continue;
            }

            if (PassThru)
            {
                WriteObject(principal);
            }
        }
    }
}
