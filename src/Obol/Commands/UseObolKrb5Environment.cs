using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Net;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsOther.Use, "ObolKrb5Environment",
    DefaultParameterSetName = StartParameterSet
)]
public sealed class UseObolKrb5Environment : UseObolEnvironmentCommandBase
{
    [Parameter]
    public ObolKrb5Provider Provider { get; set; } = ObolKrb5Provider.Default;

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string[] ServicePrincipal { get; set; } = [];

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string[] ClientPrincipal { get; set; } = [];

    [Parameter]
    public SwitchParameter SetNativeEnvironment { get; set; }

    [Parameter(ParameterSetName = StartParameterSet)]
    [ValidateRange(0, IPEndPoint.MaxPort)]
    public int Port { get; set; }

    protected override int StartPort => Port;

    protected override void BeginProcessing()
    {
        if (Krb5Config.CheckProvider(Provider) is ErrorRecord error)
        {
            ThrowTerminatingError(error);
        }

        // Checked before a KDC is started, Enter checks it again.
        if (Krb5Environment.Current is not null)
        {
            ThrowTerminatingError(EnterObolKrb5Environment.AlreadyEnteredError());
        }
    }

    protected override ErrorRecord? CheckKdc(ObolKdc kdc) => Krb5Config.CheckKdc(kdc);

    protected override void InvokeWithKdcs(ScriptBlock scriptBlock)
    {
        List<ObolPrincipal> service = FindPrincipals(ServicePrincipal);
        List<ObolPrincipal> client = FindPrincipals(ClientPrincipal);

        // The prompt is not shown while the scriptblock runs, so it is left alone.
        Krb5Environment environment = EnterObolKrb5Environment.Enter(
            this,
            Kdcs,
            Provider,
            service,
            client,
            SetNativeEnvironment,
            setPrompt: false);
        try
        {
            Invoke(scriptBlock);
        }
        finally
        {
            ExitObolKrb5Environment.Exit(this, environment);
        }
    }

    /// <summary>Finds principals by name, a name without a realm is in the realm of the first KDC.</summary>
    private List<ObolPrincipal> FindPrincipals(string[] names)
    {
        List<ObolPrincipal> principals = [];
        foreach (string name in names)
        {
            if (!PrincipalName.TryParse(name, out string[]? components, out string? realm, out string? parseError))
            {
                ThrowTerminatingError(new ErrorRecord(
                    new ArgumentException($"Invalid principal name '{name}': {parseError}"),
                    "InvalidPrincipalName",
                    ErrorCategory.InvalidArgument,
                    name));
            }

            realm ??= Kdcs[0].Realm;
            ObolKdc? kdc = Kdcs.FirstOrDefault(k => string.Equals(k.Realm, realm, StringComparison.Ordinal));
            ObolPrincipal? principal = kdc?.Store.Find(components);
            if (principal is null)
            {
                ThrowTerminatingError(new ErrorRecord(
                    new ItemNotFoundException($"The principal '{PrincipalName.Unparse(components)}@{realm}' does " +
                        "not exist"),
                    "PrincipalNotFound",
                    ErrorCategory.ObjectNotFound,
                    name));
            }
            principals.Add(principal);
        }
        return principals;
    }
}
