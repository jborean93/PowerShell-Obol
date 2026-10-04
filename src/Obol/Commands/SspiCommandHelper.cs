using System;
using System.Management.Automation;
using System.Net;

namespace Obol.Commands;

/// <summary>Shared helpers for the Windows SSPI KDC cmdlets.</summary>
internal static class SspiCommandHelper
{
    /// <summary>
    /// Checks a KDC address is a bare host or IP with no port, the SSP always uses port 88 and cannot parse one.
    /// </summary>
    /// <remarks>
    /// A bare IPv6 address has colons, so a colon only means a port when the value is not a valid IP on its own. A
    /// bracketed form such as <c>[::1]</c> or <c>[::1]:88</c> is rejected too, the SSP wants an unbracketed host.
    /// </remarks>
    public static ErrorRecord? CheckKdcAddress(string address)
    {
        // IPAddress.TryParse is lenient and accepts "[::1]" and "[::1]:88" as ::1, so reject any bracket first.
        bool bracketed = address.Contains('[') || address.Contains(']');
        if (!bracketed && IPAddress.TryParse(address, out _))
        {
            return null;
        }
        // A bare IPv6 was accepted above, so a remaining colon (or a bracket) means a port was included.
        if (bracketed || address.Contains(':'))
        {
            return new ErrorRecord(
                new ArgumentException(
                    $"The KDC address '{address}' must be a bare host name or IP address without a port, the " +
                    "Kerberos SSP always uses port 88."),
                "InvalidKdcAddress",
                ErrorCategory.InvalidArgument,
                address);
        }
        return null;
    }

    /// <summary>Infers the address type: an IP or dotted name is Inet, a single label is NetBios.</summary>
    public static ObolSspiKdcAddressType InferAddressType(string address)
        => IPAddress.TryParse(address, out _) || address.Contains('.')
            ? ObolSspiKdcAddressType.Inet
            : ObolSspiKdcAddressType.NetBios;

    /// <summary>The only port the Kerberos SSP contacts a KDC on.</summary>
    public const int KdcPort = 88;

    /// <summary>Checks a KDC can be registered with the Kerberos SSP: it is running and listens on port 88.</summary>
    /// <returns>The error to write, or null if the KDC can be used.</returns>
    public static ErrorRecord? CheckKdc(ObolKdc kdc)
    {
        if (Krb5Config.CheckRunning(kdc) is ErrorRecord error)
        {
            return error;
        }
        return kdc.Endpoint.Port == KdcPort ? null : PortError(kdc.Realm, kdc.Endpoint.Port);
    }

    /// <summary>The error for a KDC that is not on port 88, the only port the Kerberos SSP uses.</summary>
    public static ErrorRecord PortError(string realm, int port) => new(
        new ArgumentException($"The KDC for '{realm}' listens on port {port}, but Windows Kerberos always uses port " +
            $"{KdcPort}. Start the KDC on port {KdcPort}, or use the krb5 environment cmdlets for MIT krb5 or " +
            "Heimdal clients instead."),
        "SspiKdcPortNot88",
        ErrorCategory.InvalidArgument,
        port);

    /// <summary>The error written when an SSPI cmdlet runs on a platform other than Windows.</summary>
    public static ErrorRecord NotWindowsError(string cmdlet) => new(
        new PlatformNotSupportedException(
            $"{cmdlet} uses the Windows Kerberos SSP and is only supported on Windows"),
        "SspiNotSupported",
        ErrorCategory.NotImplemented,
        null);

    /// <summary>Builds an error record for a failed Kerberos SSP call.</summary>
    public static ErrorRecord SspiError(SspiKdcException exception) => new(
        exception,
        "SspiCallFailed",
        ErrorCategory.NotSpecified,
        null);
}
