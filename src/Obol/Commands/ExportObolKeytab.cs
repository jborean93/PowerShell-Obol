using System;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Management.Automation;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsData.Export, "ObolKeytab",
    DefaultParameterSetName = PrincipalParameterSet,
    SupportsShouldProcess = true
)]
public sealed class ExportObolKeytab : PSCmdlet
{
    private const string PrincipalParameterSet = "Principal";
    private const string NameParameterSet = "Name";
    private const string EntryParameterSet = "Entry";

    private readonly KeytabBuilder _keytab = new();

    [Parameter(
        Mandatory = true,
        Position = 0
    )]
    [ValidateNotNullOrEmpty]
    public string Path { get; set; } = "";

    [Parameter(
        Mandatory = true,
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
        Position = 1,
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

    [Parameter]
    public SwitchParameter Append { get; set; }

    [Parameter]
    public SwitchParameter Force { get; set; }

    protected override void BeginProcessing()
    {
        if (Append && Force)
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("Append and Force cannot be set together"),
                "AppendWithForce",
                ErrorCategory.InvalidArgument,
                null));
        }
    }

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
        // Nothing is written if every principal failed so a bad name does not leave an empty keytab behind.
        if (_keytab.IsEmpty)
        {
            return;
        }

        string path = FileCommandHelper.ResolvePath(this, Path);
        if (!ShouldProcess(path, $"Export keys of {_keytab.Names}"))
        {
            return;
        }

        ArrayBufferWriter<byte> entries = new();
        try
        {
            _keytab.Write(entries);

            FileMode mode = Append ? FileMode.OpenOrCreate : Force ? FileMode.Create : FileMode.CreateNew;
            using FileStream stream = FileCommandHelper.Open(this, path, mode, ownerOnly: true);
            if (Append && stream.Length > 0)
            {
                Span<byte> header = stackalloc byte[2];
                if (stream.Length < header.Length || stream.Read(header) != header.Length ||
                    !header.SequenceEqual(Keytab.Header))
                {
                    ThrowTerminatingError(new ErrorRecord(
                        new InvalidDataException(
                            $"The file '{path}' is not a keytab that can be appended to, only version 0x0502 " +
                            "keytabs are supported"),
                        "InvalidKeytab",
                        ErrorCategory.InvalidData,
                        path));
                }
                stream.Seek(0, SeekOrigin.End);
            }
            else
            {
                stream.Write(Keytab.Header);
            }
            stream.Write(entries.WrittenSpan);
        }
        finally
        {
            // Clear zeroes the written bytes so the keys do not stay in memory.
            entries.Clear();
        }
    }
}
