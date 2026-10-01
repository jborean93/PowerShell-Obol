using System.Management.Automation;

namespace Obol.Commands;

[Cmdlet(
    VerbsLifecycle.Stop, "ObolKdc",
    SupportsShouldProcess = true
)]
public sealed class StopObolKdc : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true
    )]
    [ValidateNotNull]
    public ObolKdc[] Kdc { get; set; } = [];

    protected override void ProcessRecord()
    {
        foreach (ObolKdc kdc in Kdc)
        {
            if (ShouldProcess($"KDC for '{kdc.Realm}' on {kdc.Endpoint}", "Stop"))
            {
                kdc.Dispose();
            }
        }
    }
}
