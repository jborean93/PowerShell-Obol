using System;
using System.Collections;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Net.Sockets;
using System.Security;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsLifecycle.Start, "ObolKdc"
)]
[OutputType(typeof(ObolKdc))]
public sealed class StartObolKdc : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0
    )]
    [ValidateNotNullOrEmpty]
    public string Realm { get; set; } = "";

    [Parameter]
    [ValidateNotNull]
    [ArgumentCompleter(typeof(AddressCompleter))]
    public IPAddress Address { get; set; } = IPAddress.Loopback;

    [Parameter]
    [ValidateRange(0, IPEndPoint.MaxPort)]
    public int Port { get; set; }

    [Parameter]
    public ObolKdcTransport Transport { get; set; } = ObolKdcTransport.Tcp | ObolKdcTransport.Udp;

    [Parameter]
    [ValidateRange(1, KdcListener.MaxUdpPayloadSize)]
    public int MaxUdpReplySize { get; set; } = KdcListener.DefaultMaxUdpReplySize;

    [Parameter]
    public SwitchParameter CaseInsensitivePrincipal { get; set; }

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string? DomainSid { get; set; }

    [Parameter]
    [ValidateNotNull]
    public IDictionary? Principal { get; set; }

    protected override void EndProcessing()
    {
        // Binding rejects undefined values but not 0, or a value created with [Enum]::ToObject.
        if (Transport == 0 || (Transport & ~(ObolKdcTransport.Tcp | ObolKdcTransport.Udp)) != 0)
        {
            ErrorRecord transportErr = new(
                new ArgumentException($"Transport must be Tcp, Udp or both, got '{Transport}'"),
                "InvalidTransport",
                ErrorCategory.InvalidArgument,
                Transport);
            ThrowTerminatingError(transportErr);
            return;
        }

        // RFC 4120 6.1 allows these in a realm but the MIT KDC cannot host one, kdb5_util cannot create the database
        // and krb5.conf cannot hold a control character. Every principal name in such a realm also needs '\'
        // escapes, so they are rejected rather than supporting a realm no other KDC can serve.
        if (Realm.AsSpan().IndexOfAny('/', '@', '\\') != -1 || Realm.Any(char.IsControl))
        {
            ErrorRecord realmErr = new(
                new ArgumentException($"The realm '{Realm}' must not contain '/', '@', '\\' or control characters"),
                "InvalidRealm",
                ErrorCategory.InvalidArgument,
                Realm);
            ThrowTerminatingError(realmErr);
            return;
        }

        uint[]? domainSid = null;
        if (DomainSid is not null && !PrincipalStore.TryParseDomainSid(DomainSid, out domainSid))
        {
            ErrorRecord sidErr = new(
                new ArgumentException(
                    $"The domain SID '{DomainSid}' must be in the form S-1-5-21-<a>-<b>-<c> where each value is a " +
                    "32-bit unsigned integer"),
                "InvalidDomainSid",
                ErrorCategory.InvalidArgument,
                DomainSid);
            ThrowTerminatingError(sidErr);
            return;
        }

        IPEndPoint endpoint = new(Address, Port);

        ObolKdc kdc;
        try
        {
            kdc = ObolKdc.Bind(Realm, endpoint, Transport, MaxUdpReplySize, CaseInsensitivePrincipal, domainSid);
        }
        catch (SocketException e)
        {
            ErrorRecord err = new(
                e,
                "KdcBindFailed",
                ErrorCategory.ResourceUnavailable,
                endpoint)
            {
                ErrorDetails = new($"Failed to start the KDC for '{Realm}' on {endpoint}: {e.Message}"),
            };
            ThrowTerminatingError(err);
            return;
        }

        // The principals are added before the KDC answers requests so a client never sees the KDC without them.
        if (Principal is not null)
        {
            try
            {
                AddPrincipals(kdc, Principal);
            }
            catch
            {
                kdc.Dispose();
                throw;
            }
        }
        kdc.Start();

        if (Runspace.DefaultRunspace is Runspace runspace)
        {
            kdc.RegisterRunspace(runspace);
        }

        WriteObject(kdc);
    }

    /// <summary>Creates the principals of -Principal, any failure is a terminating error.</summary>
    private void AddPrincipals(ObolKdc kdc, IDictionary principals)
    {
        foreach (DictionaryEntry entry in principals)
        {
            string name = LanguagePrimitives.ConvertTo<string>(entry.Key);
            object? value = entry.Value is PSObject psObject ? psObject.BaseObject : entry.Value;

            ObolPrincipalSetting setting;
            switch (value)
            {
                case null:
                    setting = new();
                    break;

                case SecureString password:
                    setting = new() { Password = password };
                    break;

                case ObolPrincipalSetting principalSetting:
                    setting = principalSetting;
                    break;

                default:
                    ThrowInvalidPrincipal(name,
                        "The value must be null for random keys, a SecureString password, or an " +
                        $"ObolPrincipalSetting, got '{value.GetType().FullName}'");
                    return;
            }

            NewObolPrincipal.Create(this, kdc, name, setting, out ErrorRecord? error);
            if (error is not null)
            {
                ThrowTerminatingError(error);
            }
        }
    }

    [DoesNotReturn]
    private void ThrowInvalidPrincipal(string name, string message)
    {
        ThrowTerminatingError(new ErrorRecord(
            new ArgumentException($"Invalid principal '{name}' in -Principal: {message}"),
            "InvalidPrincipalArgument",
            ErrorCategory.InvalidArgument,
            name));
        throw new UnreachableException();
    }
}
