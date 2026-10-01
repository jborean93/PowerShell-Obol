using System.Collections.Generic;
using System.Management.Automation;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.Remove, "ObolPrincipal",
    DefaultParameterSetName = PrincipalParameterSet,
    SupportsShouldProcess = true
)]
public sealed class RemoveObolPrincipal : PSCmdlet
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

    protected override void ProcessRecord()
    {
        IEnumerable<ObolPrincipal> principals = ParameterSetName == NameParameterSet
            ? PrincipalCommandHelper.FindByName(this, Kdc!, Name)
            : Principal;
        foreach (ObolPrincipal principal in principals)
        {
            if (!ShouldProcess(principal.FullName, "Remove principal"))
            {
                continue;
            }

            try
            {
                principal.Store.Remove(principal);
            }
            catch (PrincipalStoreException e)
            {
                WriteError(PrincipalCommandHelper.StoreError(e, principal));
            }
        }
    }
}
