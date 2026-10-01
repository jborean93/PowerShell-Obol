using System.Management.Automation;
using Kerberos.NET.Server;

namespace Obol.Commands;

[Cmdlet(
    VerbsLifecycle.Start, "ObolKdc"
)]
[OutputType(typeof(string))]
public sealed class StartObolKdc : PSCmdlet
{
    protected override void EndProcessing()
    {
        string kerberosVersion = typeof(KdcServer).Assembly.GetName().Version?.ToString() ?? "unknown";
        WriteObject($"Obol KDC using Kerberos.NET {kerberosVersion}");
    }
}
