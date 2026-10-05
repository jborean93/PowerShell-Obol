using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management.Automation;
using System.Net;

namespace Obol.Commands;

/// <summary>
/// The parameters and scriptblock handling shared by the Use-Obol*Environment cmdlets, which start a KDC or use
/// existing ones, configure Kerberos to use them while a scriptblock runs and then remove that configuration.
/// </summary>
public abstract class UseObolEnvironmentCommandBase : PSCmdlet
{
    protected const string StartParameterSet = "Start";
    protected const string KdcParameterSet = "Kdc";

    private readonly List<ObolKdc> _kdcs = [];

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = StartParameterSet
    )]
    [ValidateNotNullOrEmpty]
    public string Realm { get; set; } = "";

    [Parameter(
        Mandatory = true,
        ValueFromPipeline = true,
        ParameterSetName = KdcParameterSet
    )]
    [ValidateNotNull]
    public ObolKdc[] Kdc { get; set; } = [];

    [Parameter(
        Mandatory = true,
        Position = 1,
        ParameterSetName = StartParameterSet
    )]
    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = KdcParameterSet
    )]
    public ScriptBlock? ScriptBlock { get; set; }

    [Parameter(ParameterSetName = StartParameterSet)]
    [ValidateNotNull]
    [ArgumentCompleter(typeof(AddressCompleter))]
    public IPAddress Address { get; set; } = IPAddress.Loopback;

    [Parameter(ParameterSetName = StartParameterSet)]
    public ObolKdcTransport Transport { get; set; } = ObolKdcTransport.Tcp | ObolKdcTransport.Udp;

    [Parameter(ParameterSetName = StartParameterSet)]
    [ValidateRange(1, KdcListener.MaxUdpPayloadSize)]
    public int MaxUdpReplySize { get; set; } = KdcListener.DefaultMaxUdpReplySize;

    [Parameter(ParameterSetName = StartParameterSet)]
    public SwitchParameter CaseInsensitivePrincipal { get; set; }

    [Parameter(ParameterSetName = StartParameterSet)]
    [ValidateNotNullOrEmpty]
    public string? DomainSid { get; set; }

    [Parameter(ParameterSetName = StartParameterSet)]
    [ValidateNotNull]
    public IDictionary? Principal { get; set; }

    [Parameter]
    public SwitchParameter NoNewScope { get; set; }

    /// <summary>The KDCs to use, the ones from -Kdc or the one started with -Realm.</summary>
    protected IReadOnlyList<ObolKdc> Kdcs => _kdcs;

    /// <summary>The port a KDC started with -Realm listens on, 0 for a random port.</summary>
    protected abstract int StartPort { get; }

    /// <summary>Checks a KDC can be used, from -Kdc or after it was started with -Realm.</summary>
    /// <returns>The error to throw, or null if the KDC can be used.</returns>
    protected abstract ErrorRecord? CheckKdc(ObolKdc kdc);

    /// <summary>Configures Kerberos for <see cref="Kdcs"/>, runs the scriptblock with <see cref="Invoke"/> and then
    /// removes the configuration, even when the scriptblock fails.</summary>
    protected abstract void InvokeWithKdcs(ScriptBlock scriptBlock);

    protected override void ProcessRecord()
    {
        // The scriptblock only runs once all KDCs are received, a KDC that cannot be used stops it from running.
        foreach (ObolKdc kdc in Kdc)
        {
            if (CheckKdc(kdc) is ErrorRecord error)
            {
                ThrowTerminatingError(error);
            }
            _kdcs.Add(kdc);
        }
    }

    protected override void EndProcessing()
    {
        Debug.Assert(ScriptBlock is not null);

        ObolKdc? started = null;
        try
        {
            if (ParameterSetName == StartParameterSet)
            {
                started = StartObolKdc.Start(
                    this,
                    Realm,
                    Address,
                    StartPort,
                    Transport,
                    MaxUdpReplySize,
                    CaseInsensitivePrincipal,
                    DomainSid,
                    Principal);
                _kdcs.Add(started);

                // Checked after starting as a realm Start-ObolKdc accepts may not fit in a krb5.conf.
                if (CheckKdc(started) is ErrorRecord error)
                {
                    ThrowTerminatingError(error);
                }
            }
            else if (_kdcs.Count == 0)
            {
                ThrowTerminatingError(new ErrorRecord(
                    new ArgumentException("No KDC was given to -Kdc"),
                    "NoKdc",
                    ErrorCategory.InvalidArgument,
                    null));
            }

            InvokeWithKdcs(ScriptBlock);
        }
        finally
        {
            started?.Dispose();
        }
    }

    /// <summary>Runs the scriptblock with the KDCs as arguments, like the call or dot-source operator.</summary>
    protected void Invoke(ScriptBlock scriptBlock)
        => ScriptBlockHelper.Invoke(this, scriptBlock, [.. _kdcs], NoNewScope);
}
