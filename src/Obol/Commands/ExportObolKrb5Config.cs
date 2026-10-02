using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Text;

namespace Obol.Commands;

[Cmdlet(
    VerbsData.Export, "ObolKrb5Config",
    SupportsShouldProcess = true
)]
public sealed class ExportObolKrb5Config : PSCmdlet
{
    private readonly List<ObolKdc> _kdcs = [];

    [Parameter(
        Mandatory = true,
        Position = 0
    )]
    [ValidateNotNullOrEmpty]
    public string Path { get; set; } = "";

    [Parameter(
        Mandatory = true,
        ValueFromPipeline = true
    )]
    [ValidateNotNull]
    public ObolKdc[] Kdc { get; set; } = [];

    [Parameter]
    public SwitchParameter Force { get; set; }

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
        // Nothing is written if every KDC failed so an error does not leave an empty krb5.conf behind.
        if (_kdcs.Count == 0)
        {
            return;
        }

        string path = FileCommandHelper.ResolvePath(this, Path);
        if (!ShouldProcess(path, $"Export krb5.conf for {string.Join(", ", _kdcs)}"))
        {
            return;
        }

        byte[] content = new UTF8Encoding(false).GetBytes(Krb5Config.Create(_kdcs, Provider));
        using FileStream stream = FileCommandHelper.Open(
            this,
            path,
            Force ? FileMode.Create : FileMode.CreateNew,
            ownerOnly: false);
        stream.Write(content);
    }
}
