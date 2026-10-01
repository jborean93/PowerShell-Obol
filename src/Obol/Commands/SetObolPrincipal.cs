using System;
using System.Collections.Generic;
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
    public SwitchParameter PassThru { get; set; }

    protected override void BeginProcessing()
    {
        if (Password is not null && NewRandomKey)
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("Password and NewRandomKey cannot be set together"),
                "PasswordWithNewRandomKey",
                ErrorCategory.InvalidArgument,
                null));
        }

        if (Password is not null && Password.Length == 0)
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("The password must not be empty"),
                "EmptyPassword",
                ErrorCategory.InvalidArgument,
                null));
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

            if (!ShouldProcess(principal.FullName, "Set principal"))
            {
                continue;
            }

            try
            {
                principal.Store.Update(principal, Password, NewRandomKey, etypes, flags, aliases);
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
