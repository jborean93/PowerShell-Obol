using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Management.Automation;
using Microsoft.PowerShell.Commands;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsData.Import, "ObolKeytab",
    DefaultParameterSetName = PathParameterSet
)]
[OutputType(typeof(ObolKeytabEntry))]
public sealed class ImportObolKeytab : PSCmdlet
{
    private const string PathParameterSet = "Path";
    private const string LiteralPathParameterSet = "LiteralPath";

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ParameterSetName = PathParameterSet
    )]
    [SupportsWildcards]
    [ValidateNotNullOrEmpty]
    public string[] Path { get; set; } = [];

    [Parameter(
        Mandatory = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = LiteralPathParameterSet
    )]
    [Alias("PSPath")]
    [ValidateNotNullOrEmpty]
    public string[] LiteralPath { get; set; } = [];

    protected override void ProcessRecord()
    {
        bool literal = ParameterSetName == LiteralPathParameterSet;
        foreach (string path in literal ? LiteralPath : Path)
        {
            ProviderInfo provider;
            Collection<string> resolved;
            try
            {
                if (literal)
                {
                    resolved = [SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out provider, out _)];
                }
                else
                {
                    resolved = SessionState.Path.GetResolvedProviderPathFromPSPath(path, out provider);
                }
            }
            catch (ItemNotFoundException e)
            {
                WriteError(new ErrorRecord(e, "PathNotFound", ErrorCategory.ObjectNotFound, path));
                continue;
            }

            if (provider.ImplementingType != typeof(FileSystemProvider))
            {
                WriteError(new ErrorRecord(
                    new ArgumentException(
                        $"The path '{path}' must be a file system path, got a {provider.Name} path"),
                    "PathNotFileSystem",
                    ErrorCategory.InvalidArgument,
                    path));
                continue;
            }

            foreach (string filePath in resolved)
            {
                ReadKeytab(filePath);
            }
        }
    }

    private void ReadKeytab(string path)
    {
        byte[] data;
        try
        {
            data = File.ReadAllBytes(path);
        }
        catch (FileNotFoundException e)
        {
            WriteError(new ErrorRecord(e, "PathNotFound", ErrorCategory.ObjectNotFound, path));
            return;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            WriteError(new ErrorRecord(e, "KeytabReadFailed", ErrorCategory.ReadError, path)
            {
                ErrorDetails = new($"Failed to read '{path}': {e.Message}"),
            });
            return;
        }

        try
        {
            foreach (ObolKeytabEntry entry in Keytab.Read(data))
            {
                WriteObject(entry);
            }
        }
        catch (InvalidDataException e)
        {
            WriteError(new ErrorRecord(e, "InvalidKeytab", ErrorCategory.InvalidData, path)
            {
                ErrorDetails = new($"The file '{path}' is not a valid keytab: {e.Message}"),
            });
        }
    }
}
