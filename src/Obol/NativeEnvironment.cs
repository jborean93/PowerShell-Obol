using System;
using System.Runtime.InteropServices;

namespace Obol;

/// <summary>Reads and changes the C library's environment on Linux and macOS.</summary>
/// <remarks>
/// .NET keeps its own copy of the environment on Unix, a change through <see cref="Environment"/> is seen by child
/// processes but not by native code in the process, such as GSSAPI. setenv and unsetenv are not thread safe, a
/// native thread reading the environment at the same time can read freed memory.
/// </remarks>
internal static unsafe class NativeEnvironment
{
    // The C library is loaded with the process, the main program handle finds glibc, musl and libSystem exports.
    private static readonly Lazy<nint> s_getenv = new(() => GetExport("getenv"));
    private static readonly Lazy<nint> s_setenv = new(() => GetExport("setenv"));
    private static readonly Lazy<nint> s_unsetenv = new(() => GetExport("unsetenv"));

    public static string? Get(string name)
    {
        nint namePtr = Marshal.StringToCoTaskMemUTF8(name);
        try
        {
            nint value = ((delegate* unmanaged<nint, nint>)s_getenv.Value)(namePtr);
            return Marshal.PtrToStringUTF8(value);
        }
        finally
        {
            Marshal.FreeCoTaskMem(namePtr);
        }
    }

    /// <summary>Sets the variable, null removes it.</summary>
    public static void Set(string name, string? value)
    {
        nint namePtr = Marshal.StringToCoTaskMemUTF8(name);
        nint valuePtr = value is null ? 0 : Marshal.StringToCoTaskMemUTF8(value);
        try
        {
            int rc = value is null
                ? ((delegate* unmanaged<nint, int>)s_unsetenv.Value)(namePtr)
                : ((delegate* unmanaged<nint, nint, int, int>)s_setenv.Value)(namePtr, valuePtr, 1);
            if (rc != 0)
            {
                throw new InvalidOperationException($"Failed to set the native environment variable '{name}'");
            }
        }
        finally
        {
            Marshal.FreeCoTaskMem(namePtr);
            Marshal.FreeCoTaskMem(valuePtr);
        }
    }

    private static nint GetExport(string name)
        => NativeLibrary.GetExport(NativeLibrary.GetMainProgramHandle(), name);
}
