using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace Obol;

/// <summary>
/// Sends the Kerberos SSP LSA messages that steer KDC selection on Windows.
/// </summary>
/// <remarks>
/// The per-process pin (<see cref="PinKdc"/> / <see cref="UnpinAllKdcs"/>) uses an untrusted LSA connection and needs
/// no privileges. The machine-wide binding cache (<see cref="AddBinding"/>, <see cref="QueryBindings"/>,
/// <see cref="PurgeBindings"/>) uses a trusted connection which requires SeTcbPrivilege, so the caller must wrap those
/// in a <see cref="SystemImpersonation"/>. All pointers in a submitted request are absolute into the submit buffer;
/// the SSP rebases them with the client buffer base supplied by LsaCallAuthenticationPackage.
/// </remarks>
[SupportedOSPlatform("windows")]
internal static partial class SspiKdc
{
    // KERB_PROTOCOL_MESSAGE_TYPE values, the binding cache ones are from ntsecapi.h, the pin ones are undocumented.
    private const int KerbPinKdcMessage = 0x400;
    private const int KerbUnpinAllKdcsMessage = 0x401;
    private const int KerbAddBindingCacheEntryExMessage = 27;
    private const int KerbQueryBindingCacheMessage = 28;
    private const int KerbPurgeBindingCacheMessage = 29;

    // The request header the two string requests (pin and add binding) share, the strings follow it.
    private const int RequestHeaderSize = 0x30;

    // The size of a KERB_BINDING_CACHE_ENTRY_DATA in a KERB_QUERY_BINDING_CACHE_RESPONSE.
    private const int BindingEntrySize = 0x48;

    /// <summary>Pins a realm to a KDC for the current thread (KerbPinKdc).</summary>
    public static void PinKdc(string realm, string kdcAddress, int flags)
    {
        nint buffer = BuildTwoStringRequest(KerbPinKdcMessage, realm, kdcAddress, flags, 0, out int length);
        try
        {
            Execute(trusted: false, buffer, length, static (_, _) => true);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Removes every pin the current process made (KerbUnpinAllKdcs).</summary>
    public static void UnpinAllKdcs()
        => ExecuteMessageOnly(trusted: false, KerbUnpinAllKdcsMessage);

    /// <summary>Adds a realm to KDC binding to the machine-wide cache (KerbAddBindingCacheEntryEx).</summary>
    public static void AddBinding(string realm, string kdcAddress, int addressType, int dcFlags)
    {
        nint buffer = BuildTwoStringRequest(
            KerbAddBindingCacheEntryExMessage, realm, kdcAddress, addressType, dcFlags, out int length);
        try
        {
            Execute(trusted: true, buffer, length, static (_, _) => true);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Reads the machine-wide binding cache (KerbQueryBindingCache).</summary>
    public static List<ObolSspiKdc> QueryBindings()
    {
        nint buffer = BuildMessageOnlyRequest(KerbQueryBindingCacheMessage, out int length);
        try
        {
            return Execute(trusted: true, buffer, length, ParseBindings);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Flushes the machine-wide binding cache (KerbPurgeBindingCache).</summary>
    public static void PurgeBindings()
        => ExecuteMessageOnly(trusted: true, KerbPurgeBindingCacheMessage);

    private static void ExecuteMessageOnly(bool trusted, int messageType)
    {
        nint buffer = BuildMessageOnlyRequest(messageType, out int length);
        try
        {
            Execute(trusted, buffer, length, static (_, _) => true);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Opens the LSA connection, submits the request to the Kerberos package and parses the reply.</summary>
    private static T Execute<T>(bool trusted, nint submit, int submitLength, Func<nint, uint, T> parse)
    {
        nint lsaHandle = 0;
        nint returnBuffer = 0;
        nint packageName = 0;
        try
        {
            int status = trusted ? RegisterLogonProcess(out lsaHandle) : LsaConnectUntrusted(out lsaHandle);
            Check(status, trusted ? "LsaRegisterLogonProcess" : "LsaConnectUntrusted");

            packageName = BuildLsaString("Kerberos", out LSA_STRING package);
            status = LsaLookupAuthenticationPackage(lsaHandle, ref package, out uint authPackage);
            Check(status, "LsaLookupAuthenticationPackage");

            status = LsaCallAuthenticationPackage(
                lsaHandle, authPackage, submit, (uint)submitLength,
                out returnBuffer, out uint returnLength, out int protocolStatus);
            Check(status, "LsaCallAuthenticationPackage");
            Check(protocolStatus, "The Kerberos SSP");

            return parse(returnBuffer, returnLength);
        }
        finally
        {
            if (packageName != 0)
            {
                Marshal.FreeHGlobal(packageName);
            }
            if (returnBuffer != 0)
            {
                LsaFreeReturnBuffer(returnBuffer);
            }
            if (lsaHandle != 0)
            {
                LsaDeregisterLogonProcess(lsaHandle);
            }
        }
    }

    private static int RegisterLogonProcess(out nint handle)
    {
        nint namePtr = BuildLsaString("Obol", out LSA_STRING name);
        try
        {
            return LsaRegisterLogonProcess(ref name, out handle, out _);
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
        }
    }

    /// <summary>Throws on an NTSTATUS failure. A non-negative value is ok (0x40000000 is already exists).</summary>
    private static void Check(int status, string operation)
    {
        if (status < 0)
        {
            throw SspiKdcException.FromNtStatus(operation, status, (int)LsaNtStatusToWinError(status));
        }
    }

    /// <summary>Builds a request that is just a message type, padded to 8 bytes as the SSP requires.</summary>
    private static nint BuildMessageOnlyRequest(int messageType, out int length)
    {
        length = 8;
        nint buffer = Marshal.AllocHGlobal(length);
        Marshal.WriteInt64(buffer, 0, 0);
        Marshal.WriteInt32(buffer, 0, messageType);
        return buffer;
    }

    /// <summary>
    /// Builds a request with two UNICODE_STRINGs and two trailing DWORDs, the layout the pin and add-binding
    /// requests share: message type at 0x00, the strings at 0x08 and 0x18, the DWORDs at 0x28 and 0x2C, data at 0x30.
    /// </summary>
    private static nint BuildTwoStringRequest(
        int messageType, string first, string second, int field28, int field2C, out int length)
    {
        byte[] firstBytes = Encoding.Unicode.GetBytes(first);
        byte[] secondBytes = Encoding.Unicode.GetBytes(second);
        if (firstBytes.Length is 0 or > 0xFFFF || secondBytes.Length is 0 or > 0xFFFF)
        {
            throw SspiKdcException.Create("The realm and KDC address must be between 1 and 32767 characters");
        }

        length = RequestHeaderSize + firstBytes.Length + secondBytes.Length;
        nint buffer = Marshal.AllocHGlobal(length);
        try
        {
            for (int offset = 0; offset < RequestHeaderSize; offset += 8)
            {
                Marshal.WriteInt64(buffer, offset, 0);
            }

            nint firstData = buffer + RequestHeaderSize;
            nint secondData = buffer + RequestHeaderSize + firstBytes.Length;

            Marshal.WriteInt32(buffer, 0x00, messageType);

            Marshal.WriteInt16(buffer, 0x08, (short)firstBytes.Length);
            Marshal.WriteInt16(buffer, 0x0A, (short)firstBytes.Length);
            Marshal.WriteIntPtr(buffer, 0x10, firstData);

            Marshal.WriteInt16(buffer, 0x18, (short)secondBytes.Length);
            Marshal.WriteInt16(buffer, 0x1A, (short)secondBytes.Length);
            Marshal.WriteIntPtr(buffer, 0x20, secondData);

            Marshal.WriteInt32(buffer, 0x28, field28);
            Marshal.WriteInt32(buffer, 0x2C, field2C);

            Marshal.Copy(firstBytes, 0, firstData, firstBytes.Length);
            Marshal.Copy(secondBytes, 0, secondData, secondBytes.Length);
            return buffer;
        }
        catch
        {
            Marshal.FreeHGlobal(buffer);
            throw;
        }
    }

    /// <summary>Parses a KERB_QUERY_BINDING_CACHE_RESPONSE into the public binding objects.</summary>
    private static List<ObolSspiKdc> ParseBindings(nint response, uint responseLength)
    {
        List<ObolSspiKdc> bindings = [];
        if (response == 0)
        {
            return bindings;
        }

        int count = Marshal.ReadInt32(response, 4);
        nint entries = Marshal.ReadIntPtr(response, 8);
        if (entries == 0)
        {
            return bindings;
        }

        for (int i = 0; i < count; i++)
        {
            nint entry = entries + (i * BindingEntrySize);

            // DiscoveryTime is the GetTickCount64 value, milliseconds since boot, when the entry was cached.
            ulong discoveryTicks = (ulong)Marshal.ReadInt64(entry, 0x00);
            DateTime discoveryTime = TickCountToLocalTime(discoveryTicks);

            string realm = ReadUnicodeString(entry, 0x08);
            string kdcAddress = ReadUnicodeString(entry, 0x18);
            ObolSspiKdcAddressType addressType = (ObolSspiKdcAddressType)Marshal.ReadInt32(entry, 0x28);
            ObolSspiDcLocatorFlags bindingFlags = (ObolSspiDcLocatorFlags)(uint)Marshal.ReadInt32(entry, 0x2C);
            ObolSspiDcFlags dcFlags = (ObolSspiDcFlags)(uint)Marshal.ReadInt32(entry, 0x30);
            ObolSspiKdcCacheFlags cacheFlags = (ObolSspiKdcCacheFlags)(uint)Marshal.ReadInt32(entry, 0x34);
            string kdcName = ReadUnicodeString(entry, 0x38);

            bindings.Add(ObolSspiKdc.ForMachine(
                realm, kdcAddress, dcFlags, discoveryTime, kdcName, addressType, bindingFlags, cacheFlags));
        }
        return bindings;
    }

    /// <summary>Converts a GetTickCount64 value from earlier in this boot to the local time it was taken.</summary>
    private static DateTime TickCountToLocalTime(ulong ticks)
    {
        // Environment.TickCount64 is GetTickCount64 on Windows. A value ahead of it is not expected, use now.
        ulong now = (ulong)Environment.TickCount64;
        double elapsed = ticks > now ? 0 : now - ticks;
        return DateTime.Now - TimeSpan.FromMilliseconds(elapsed);
    }

    /// <summary>Reads a UNICODE_STRING at <paramref name="offset"/> in <paramref name="structBase"/>.</summary>
    private static string ReadUnicodeString(nint structBase, int offset)
    {
        ushort byteLength = (ushort)Marshal.ReadInt16(structBase, offset);
        nint buffer = Marshal.ReadIntPtr(structBase, offset + 8);
        if (buffer == 0 || byteLength == 0)
        {
            return "";
        }
        return Marshal.PtrToStringUni(buffer, byteLength / 2) ?? "";
    }

    private static nint BuildLsaString(string value, out LSA_STRING str)
    {
        nint ptr = Marshal.StringToHGlobalAnsi(value);
        str = new LSA_STRING
        {
            Length = (ushort)value.Length,
            MaximumLength = (ushort)(value.Length + 1),
            Buffer = ptr,
        };
        return ptr;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public nint Buffer;
    }

    [LibraryImport("secur32.dll")]
    private static partial int LsaConnectUntrusted(out nint lsaHandle);

    [LibraryImport("secur32.dll")]
    private static partial int LsaRegisterLogonProcess(ref LSA_STRING logonProcessName, out nint lsaHandle,
        out nint securityMode);

    [LibraryImport("secur32.dll")]
    private static partial int LsaLookupAuthenticationPackage(nint lsaHandle, ref LSA_STRING packageName,
        out uint authenticationPackage);

    [LibraryImport("secur32.dll")]
    private static partial int LsaCallAuthenticationPackage(nint lsaHandle, uint authenticationPackage,
        nint protocolSubmitBuffer, uint submitBufferLength, out nint protocolReturnBuffer,
        out uint returnBufferLength, out int protocolStatus);

    [LibraryImport("secur32.dll")]
    private static partial int LsaFreeReturnBuffer(nint buffer);

    [LibraryImport("secur32.dll")]
    private static partial int LsaDeregisterLogonProcess(nint lsaHandle);

    [LibraryImport("advapi32.dll")]
    private static partial uint LsaNtStatusToWinError(int status);
}
