using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace Obol;

/// <summary>
/// Makes <c>SeTcbPrivilege</c> available for the Kerberos binding cache LSA calls, impersonating SYSTEM if needed.
/// </summary>
/// <remarks>
/// The binding cache handlers in LSASS require <c>SeTcbPrivilege</c>, normally held only by SYSTEM. This works on the
/// caller's effective token, the thread's impersonation token if it is impersonating, otherwise the process token. If
/// that token already holds the privilege (the caller is SYSTEM, or has been granted the right) it is simply enabled.
/// Otherwise, like <c>klist</c>, it enables <c>SeDebugPrivilege</c>, finds a SYSTEM owned process, duplicates its
/// token and impersonates it on the calling thread, which <see cref="Dispose"/> reverts. The caller must keep the OS
/// thread for the LSA call, so do the whole call before disposing.
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed partial class SystemImpersonation : IDisposable
{
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint TOKEN_IMPERSONATE = 0x0004;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint SE_PRIVILEGE_ENABLED = 0x0002;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const int SecurityImpersonation = 2;
    private const int TokenImpersonation = 2;
    private const int TokenUser = 1;
    private const int ERROR_NOT_ALL_ASSIGNED = 1300;
    private const int ERROR_NO_TOKEN = 1008;
    private const string SE_TCB_NAME = "SeTcbPrivilege";
    private const string SE_DEBUG_NAME = "SeDebugPrivilege";

    private readonly nint _effectiveToken;
    private readonly nint _impersonationToken;
    private readonly bool _impersonating;
    private readonly List<string> _enabledPrivileges;
    private bool _disposed;

    private SystemImpersonation(nint effectiveToken, nint impersonationToken, bool impersonating,
        List<string> enabledPrivileges)
    {
        _effectiveToken = effectiveToken;
        _impersonationToken = impersonationToken;
        _impersonating = impersonating;
        _enabledPrivileges = enabledPrivileges;
    }

    /// <summary>Enables SeTcbPrivilege, impersonating SYSTEM if the effective token does not hold it.</summary>
    public static SystemImpersonation Acquire()
    {
        nint effectiveToken = OpenEffectiveToken();
        nint impersonationToken = 0;
        bool impersonating = false;
        List<string> enabled = [];
        try
        {
            // The effective token already holds SeTcbPrivilege (SYSTEM, or granted the right), just enable it.
            if (TryEnablePrivilege(effectiveToken, SE_TCB_NAME))
            {
                enabled.Add(SE_TCB_NAME);
                return new SystemImpersonation(effectiveToken, 0, false, enabled);
            }

            // SeDebugPrivilege lets an administrator open a SYSTEM process to borrow its token.
            if (!TryEnablePrivilege(effectiveToken, SE_DEBUG_NAME))
            {
                throw SspiKdcException.Create(
                    "The Kerberos binding cache requires SeTcbPrivilege. Run as an administrator so SYSTEM can be " +
                    "impersonated, or run the session as SYSTEM directly.");
            }
            enabled.Add(SE_DEBUG_NAME);

            impersonationToken = DuplicateSystemToken();
            if (!ImpersonateLoggedOnUser(impersonationToken))
            {
                throw SspiKdcException.FromWin32("ImpersonateLoggedOnUser", Marshal.GetLastPInvokeError());
            }
            impersonating = true;

            return new SystemImpersonation(effectiveToken, impersonationToken, true, enabled);
        }
        catch
        {
            if (impersonating)
            {
                RevertToSelf();
            }
            if (impersonationToken != 0)
            {
                CloseHandle(impersonationToken);
            }
            foreach (string name in enabled)
            {
                TryDisablePrivilege(effectiveToken, name);
            }
            CloseHandle(effectiveToken);
            throw;
        }
    }

    /// <summary>Opens the caller's effective token: the thread impersonation token, or the process token.</summary>
    private static nint OpenEffectiveToken()
    {
        if (OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, openAsSelf: true,
            out nint threadToken))
        {
            return threadToken;
        }

        int error = Marshal.GetLastPInvokeError();
        if (error != ERROR_NO_TOKEN)
        {
            throw SspiKdcException.FromWin32("OpenThreadToken", error);
        }

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out nint processToken))
        {
            throw SspiKdcException.FromWin32("OpenProcessToken", Marshal.GetLastPInvokeError());
        }
        return processToken;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        if (_impersonating)
        {
            RevertToSelf();
        }
        if (_impersonationToken != 0)
        {
            CloseHandle(_impersonationToken);
        }
        if (_effectiveToken != 0)
        {
            foreach (string name in _enabledPrivileges)
            {
                TryDisablePrivilege(_effectiveToken, name);
            }
            CloseHandle(_effectiveToken);
        }
    }

    /// <summary>
    /// Finds a SYSTEM process whose token grants SeTcbPrivilege and returns an impersonation token with it enabled.
    /// </summary>
    /// <remarks>
    /// Not every SYSTEM process has the full privilege set, so the privilege is enabled while searching and a process
    /// that does not grant it is skipped. Full SYSTEM processes such as winlogon, lsass or services qualify.
    /// </remarks>
    private static nint DuplicateSystemToken()
    {
        SecurityIdentifier system = new(WellKnownSidType.LocalSystemSid, null);
        foreach (Process process in Process.GetProcesses())
        {
            nint handle = 0;
            nint token = 0;
            nint duplicate = 0;
            try
            {
                handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)process.Id);
                if (handle == 0 || !OpenProcessToken(handle, TOKEN_DUPLICATE | TOKEN_QUERY, out token))
                {
                    continue;
                }
                if (!IsLocalSystem(token, system))
                {
                    continue;
                }
                if (!DuplicateTokenEx(
                        token,
                        TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES,
                        0,
                        SecurityImpersonation,
                        TokenImpersonation,
                        out duplicate))
                {
                    continue;
                }

                // SYSTEM holds SeTcbPrivilege but it is disabled by default, the LSA check needs it enabled, and some
                // SYSTEM processes do not hold it at all, so keep looking until one does.
                if (TryEnablePrivilege(duplicate, SE_TCB_NAME))
                {
                    nint found = duplicate;
                    duplicate = 0;
                    return found;
                }
            }
            finally
            {
                if (duplicate != 0)
                {
                    CloseHandle(duplicate);
                }
                if (token != 0)
                {
                    CloseHandle(token);
                }
                if (handle != 0)
                {
                    CloseHandle(handle);
                }
                process.Dispose();
            }
        }

        throw SspiKdcException.Create("Could not find a SYSTEM process with SeTcbPrivilege to impersonate");
    }

    /// <summary>Checks whether the token's user is the local SYSTEM account.</summary>
    private static bool IsLocalSystem(nint token, SecurityIdentifier system)
    {
        GetTokenInformation(token, TokenUser, 0, 0, out uint length);
        if (length == 0)
        {
            return false;
        }

        nint buffer = Marshal.AllocHGlobal((int)length);
        try
        {
            if (!GetTokenInformation(token, TokenUser, buffer, length, out _))
            {
                return false;
            }

            // TOKEN_USER starts with SID_AND_ATTRIBUTES whose first field is the SID pointer.
            nint sid = Marshal.ReadIntPtr(buffer);
            return sid != 0 && new SecurityIdentifier(sid).Equals(system);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Enables a privilege on the token, returns false if the token does not hold it.</summary>
    private static bool TryEnablePrivilege(nint token, string name)
    {
        if (!LookupPrivilegeValue(null, name, out LUID luid))
        {
            throw SspiKdcException.FromWin32($"LookupPrivilegeValue({name})", Marshal.GetLastPInvokeError());
        }

        TOKEN_PRIVILEGES privileges = new()
        {
            PrivilegeCount = 1,
            Luid = luid,
            Attributes = SE_PRIVILEGE_ENABLED,
        };
        if (!AdjustTokenPrivileges(token, false, ref privileges, 0, 0, 0))
        {
            throw SspiKdcException.FromWin32($"AdjustTokenPrivileges({name})", Marshal.GetLastPInvokeError());
        }

        // AdjustTokenPrivileges succeeds even when the privilege is not held, the error says which.
        return Marshal.GetLastPInvokeError() != ERROR_NOT_ALL_ASSIGNED;
    }

    /// <summary>Disables a privilege, ignoring failures as this is cleanup.</summary>
    private static void TryDisablePrivilege(nint token, string name)
    {
        if (!LookupPrivilegeValue(null, name, out LUID luid))
        {
            return;
        }

        TOKEN_PRIVILEGES privileges = new()
        {
            PrivilegeCount = 1,
            Luid = luid,
            Attributes = 0,
        };
        AdjustTokenPrivileges(token, false, ref privileges, 0, 0, 0);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentThread();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenProcess(uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(nint processHandle, uint desiredAccess, out nint tokenHandle);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenThreadToken(nint threadHandle, uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool openAsSelf, out nint tokenHandle);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16,
        EntryPoint = "LookupPrivilegeValueW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LookupPrivilegeValue(string? systemName, string name, out LUID luid);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AdjustTokenPrivileges(nint tokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges, ref TOKEN_PRIVILEGES newState,
        uint bufferLength, nint previousState, nint returnLength);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(nint tokenHandle, int tokenInformationClass,
        nint tokenInformation, uint tokenInformationLength, out uint returnLength);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DuplicateTokenEx(nint existingToken, uint desiredAccess, nint tokenAttributes,
        int impersonationLevel, int tokenType, out nint newToken);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ImpersonateLoggedOnUser(nint token);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool RevertToSelf();
}
