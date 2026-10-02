using System;
using System.IO;
using System.Management.Automation;
using Microsoft.PowerShell.Commands;

namespace Obol.Commands;

/// <summary>Path handling shared by the cmdlets that write files.</summary>
internal static class FileCommandHelper
{
    /// <summary>Resolves a PowerShell path to a file system path, the file does not need to exist.</summary>
    /// <remarks>A path that is not on the FileSystem provider is a terminating error.</remarks>
    public static string ResolvePath(PSCmdlet cmdlet, string path)
    {
        string resolved = cmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
            path,
            out ProviderInfo provider,
            out _);
        if (provider.ImplementingType != typeof(FileSystemProvider))
        {
            cmdlet.ThrowTerminatingError(new ErrorRecord(
                new ArgumentException($"The path '{path}' must be a file system path, got a {provider.Name} path"),
                "PathNotFileSystem",
                ErrorCategory.InvalidArgument,
                path));
        }
        return resolved;
    }

    /// <summary>Opens a file for writing, a failure is a terminating error.</summary>
    /// <param name="cmdlet">The cmdlet to throw the error for.</param>
    /// <param name="path">The resolved file system path.</param>
    /// <param name="mode">How to open the file, CreateNew fails with FileAlreadyExists if the file exists.</param>
    /// <param name="ownerOnly">Create the file readable only by the current user on Linux and macOS.</param>
    public static FileStream Open(PSCmdlet cmdlet, string path, FileMode mode, bool ownerOnly)
    {
        FileStreamOptions options = new()
        {
            Mode = mode,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
        };
        if (ownerOnly && !OperatingSystem.IsWindows())
        {
            // Only applies when the file is created, an existing file keeps its mode.
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        try
        {
            return new FileStream(path, options);
        }
        catch (IOException e) when (mode == FileMode.CreateNew && File.Exists(path))
        {
            cmdlet.ThrowTerminatingError(new ErrorRecord(
                e,
                "FileAlreadyExists",
                ErrorCategory.ResourceExists,
                path)
            {
                ErrorDetails = new($"The file '{path}' already exists, use -Force to overwrite it"),
            });
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            cmdlet.ThrowTerminatingError(new ErrorRecord(
                e,
                "FileOpenFailed",
                ErrorCategory.WriteError,
                path)
            {
                ErrorDetails = new($"Failed to open '{path}': {e.Message}"),
            });
        }
        throw new InvalidOperationException("Unreachable");
    }
}
