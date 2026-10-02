using System.Buffers;
using System.Management.Automation;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsData.ConvertTo, "ObolKeytab",
    DefaultParameterSetName = PrincipalParameterSet
)]
[OutputType(typeof(byte[]))]
public sealed class ConvertToObolKeytab : PSCmdlet
{
    private const string PrincipalParameterSet = "Principal";
    private const string NameParameterSet = "Name";
    private const string EntryParameterSet = "Entry";

    private readonly KeytabBuilder _keytab = new();

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

    [Parameter(
        Mandatory = true,
        ValueFromPipeline = true,
        ParameterSetName = EntryParameterSet
    )]
    [ValidateNotNull]
    public ObolKeytabEntry[] Entry { get; set; } = [];

    protected override void ProcessRecord()
    {
        if (ParameterSetName == EntryParameterSet)
        {
            _keytab.Add(Entry);
        }
        else
        {
            _keytab.Add(ParameterSetName == NameParameterSet
                ? PrincipalCommandHelper.FindByName(this, Kdc!, Name)
                : Principal);
        }
    }

    protected override void EndProcessing()
    {
        // Nothing is output if every principal failed, like Export-ObolKeytab does not write a file.
        if (_keytab.IsEmpty)
        {
            return;
        }

        ArrayBufferWriter<byte> data = new();
        data.Write(Keytab.Header);
        _keytab.Write(data);

        // A single byte[] rather than each byte, the caller owns the keys in it.
        WriteObject(data.WrittenSpan.ToArray());
        data.Clear();
    }
}
