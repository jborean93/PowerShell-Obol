using System;
using System.ComponentModel;

namespace Obol;

/// <summary>
/// Thrown when a Kerberos SSP LSA call, or the Windows configuration an SSPI environment sets up, used by the SSPI
/// cmdlets fails.
/// </summary>
internal sealed class SspiKdcException : Exception
{
    /// <summary>The NTSTATUS the operation failed with.</summary>
    public int NtStatus { get; }

    /// <summary>The Win32 error the NTSTATUS maps to, if known.</summary>
    public int Win32Error { get; }

    private SspiKdcException(string message, int ntStatus, int win32Error, Exception? innerException = null)
        : base(message, innerException)
    {
        NtStatus = ntStatus;
        Win32Error = win32Error;
    }

    /// <summary>Builds an exception for an NTSTATUS failure, mapping it to a Win32 message.</summary>
    public static SspiKdcException FromNtStatus(string operation, int ntStatus, int win32Error)
    {
        string detail = win32Error == 0
            ? $"NTSTATUS 0x{ntStatus:X8}"
            : $"{new Win32Exception(win32Error).Message} (NTSTATUS 0x{ntStatus:X8})";
        return new SspiKdcException($"{operation} failed: {detail}", ntStatus, win32Error);
    }

    /// <summary>Builds an exception for a Win32 failure from GetLastError.</summary>
    public static SspiKdcException FromWin32(string operation, int win32Error)
        => new($"{operation} failed: {new Win32Exception(win32Error).Message}", 0, win32Error);

    /// <summary>Builds an exception with a plain message.</summary>
    public static SspiKdcException Create(string message) => new(message, 0, 0);

    /// <summary>Builds an exception for a failed operation, the message of the cause is appended.</summary>
    public static SspiKdcException Create(string operation, Exception innerException)
        => new($"{operation} failed: {innerException.Message}", 0, 0, innerException);
}
