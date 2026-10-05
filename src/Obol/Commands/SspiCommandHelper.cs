using System;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Principal;

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

    /// <summary>
    /// Checks a KDC can be registered with the Kerberos SSP: it is running, listens on port 88 and its realm can be
    /// used with the scope.
    /// </summary>
    /// <returns>The error to write, or null if the KDC can be used.</returns>
    public static ErrorRecord? CheckKdc(ObolKdc kdc, ObolSspiKdcScope scope)
    {
        if (Krb5Config.CheckRunning(kdc) is ErrorRecord error)
        {
            return error;
        }
        if (kdc.Endpoint.Port != KdcPort)
        {
            return PortError(kdc.Realm, kdc.Endpoint.Port);
        }

        string? realmError = scope switch
        {
            // The realm is a registry key name.
            ObolSspiKdcScope.MitRealm when kdc.Realm.Contains('\\') => "must not contain a backslash",
            ObolSspiKdcScope.DcLocator when !IsDnsDomainName(kdc.Realm) =>
                "must be a DNS domain name with at least two labels of letters, digits and hyphens",
            _ => null,
        };
        if (realmError is null)
        {
            return null;
        }

        return new ErrorRecord(
            new ArgumentException($"The realm '{kdc.Realm}' cannot be used with scope {scope}, it {realmError}."),
            "InvalidSspiRealm",
            ErrorCategory.InvalidArgument,
            kdc);
    }

    /// <summary>
    /// Checks the realm is a DNS name the DC locator can look up and an NRPT rule can match, such as EXAMPLE.TEST.
    /// </summary>
    private static bool IsDnsDomainName(string realm)
    {
        string[] labels = realm.Split('.');
        if (labels.Length < 2 || realm.Length > 253)
        {
            return false;
        }

        foreach (string label in labels)
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-' ||
                !label.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>Checks the process is elevated, the scopes that write HKLM need administrator rights.</summary>
    /// <returns>The error to throw, or null if the scope needs no rights or the process has them.</returns>
    [SupportedOSPlatform("windows")]
    public static ErrorRecord? CheckAdministrator(ObolSspiKdcScope scope)
    {
        if (scope is not (ObolSspiKdcScope.MitRealm or ObolSspiKdcScope.DcLocator))
        {
            return null;
        }

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            return null;
        }

        return new ErrorRecord(
            new UnauthorizedAccessException(
                $"Scope {scope} changes the machine configuration and needs PowerShell to run as administrator"),
            "SspiScopeNeedsAdministrator",
            ErrorCategory.PermissionDenied,
            scope);
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

    /// <summary>Builds an error record for Windows configuration an SSPI environment would have to change.</summary>
    public static ErrorRecord ConflictError(SspiConflictException exception) => new(
        exception,
        "SspiConfigurationExists",
        ErrorCategory.ResourceExists,
        null);

    /// <summary>Builds an error record for a failed Kerberos SSP call.</summary>
    public static ErrorRecord SspiError(SspiKdcException exception) => new(
        exception,
        "SspiCallFailed",
        ErrorCategory.NotSpecified,
        null);
}
