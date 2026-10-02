using System.Collections.Generic;
using System.Management.Automation;

namespace Obol.Commands;

[Cmdlet(
    VerbsData.ConvertTo, "ObolKrb5Config"
)]
[OutputType(typeof(string))]
public sealed class ConvertToObolKrb5Config : PSCmdlet
{
    private readonly List<ObolKdc> _kdcs = [];

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true
    )]
    [ValidateNotNull]
    public ObolKdc[] Kdc { get; set; } = [];

    [Parameter]
    public ObolKrb5Provider Provider { get; set; } = ObolKrb5Provider.Default;

    protected override void BeginProcessing()
    {
        if (Krb5Config.CheckProvider(Provider) is ErrorRecord error)
        {
            ThrowTerminatingError(error);
        }
    }

    protected override void ProcessRecord()
    {
        foreach (ObolKdc kdc in Kdc)
        {
            if (Krb5Config.CheckKdc(kdc) is ErrorRecord error)
            {
                WriteError(error);
                continue;
            }
            _kdcs.Add(kdc);
        }
    }

    protected override void EndProcessing()
    {
        if (_kdcs.Count > 0)
        {
            WriteObject(Krb5Config.Create(_kdcs, Provider));
        }
    }
}
