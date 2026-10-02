using System.Buffers;
using System.IO;
using System.Management.Automation;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsData.ConvertFrom, "ObolKeytab"
)]
[OutputType(typeof(ObolKeytabEntry))]
public sealed class ConvertFromObolKeytab : PSCmdlet
{
    private readonly ArrayBufferWriter<byte> _data = new();

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true
    )]
    [ValidateNotNull]
    public byte[] InputObject { get; set; } = [];

    protected override void ProcessRecord()
    {
        // A byte[] in a variable is unrolled by the pipeline into single bytes, so every input is joined and read
        // as one keytab at the end.
        _data.Write(InputObject);
    }

    protected override void EndProcessing()
    {
        try
        {
            foreach (ObolKeytabEntry entry in Keytab.Read(_data.WrittenSpan))
            {
                WriteObject(entry);
            }
        }
        catch (InvalidDataException e)
        {
            WriteError(new ErrorRecord(e, "InvalidKeytab", ErrorCategory.InvalidData, null)
            {
                ErrorDetails = new($"The data is not a valid keytab: {e.Message}"),
            });
        }
        finally
        {
            // Clear zeroes the copied bytes so the keys do not stay in memory.
            _data.Clear();
        }
    }
}
