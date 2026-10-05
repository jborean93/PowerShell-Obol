using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Threading;

namespace Obol.Commands;

[Cmdlet(
    VerbsDiagnostic.Trace, "ObolKdc",
    DefaultParameterSetName = StreamParameterSet
)]
[OutputType(typeof(ObolKdcEvent), typeof(ObolDnsEvent), typeof(ObolLdapEvent))]
public sealed class TraceObolKdc : PSCmdlet, IDisposable
{
    private const string StreamParameterSet = "Stream";
    private const string ScriptBlockParameterSet = "ScriptBlock";

    private readonly List<ObolKdc> _kdcs = [];
    private readonly BlockingCollection<ObolTraceEvent> _events = [];
    private readonly CancellationTokenSource _cts = new();

    [Parameter(
        Mandatory = true,
        ValueFromPipeline = true
    )]
    [ValidateNotNullOrEmpty]
    public ObolKdc[] Kdc { get; set; } = [];

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = ScriptBlockParameterSet
    )]
    public ScriptBlock? ScriptBlock { get; set; }

    [Parameter]
    [ValidateRange(ObolTraceType.Kdc, ObolTraceType.All)]
    public ObolTraceType Include { get; set; } = ObolTraceType.All;

    protected override void ProcessRecord()
    {
        foreach (ObolKdc kdc in Kdc)
        {
            if (Krb5Config.CheckRunning(kdc) is ErrorRecord error)
            {
                ThrowTerminatingError(error);
            }
            if (!_kdcs.Contains(kdc))
            {
                _kdcs.Add(kdc);
            }
        }
    }

    protected override void EndProcessing()
    {
        // An empty -Kdc fails validation, this is an empty pipeline.
        if (_kdcs.Count == 0)
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("No KDC was given to -Kdc"),
                "NoKdc",
                ErrorCategory.InvalidArgument,
                null));
        }

        foreach (ObolKdc kdc in _kdcs)
        {
            if (Include.HasFlag(ObolTraceType.Kdc))
            {
                kdc.RequestProcessed += OnEvent;
            }
            if (Include.HasFlag(ObolTraceType.Dns))
            {
                kdc.DnsRequestProcessed += OnEvent;
            }
            if (Include.HasFlag(ObolTraceType.Ldap))
            {
                kdc.LdapRequestProcessed += OnEvent;
            }
            kdc.Stopped += OnStopped;
        }
        try
        {
            if (ScriptBlock is not null)
            {
                Capture(ScriptBlock);
            }
            else
            {
                Stream();
            }
        }
        finally
        {
            foreach (ObolKdc kdc in _kdcs)
            {
                kdc.RequestProcessed -= OnEvent;
                kdc.DnsRequestProcessed -= OnEvent;
                kdc.LdapRequestProcessed -= OnEvent;
                kdc.Stopped -= OnStopped;
            }
        }
    }

    protected override void StopProcessing() => _cts.Cancel();

    public void Dispose()
    {
        _cts.Dispose();
        _events.Dispose();
    }

    /// <summary>Writes the events as they happen until the pipeline is stopped or every KDC has stopped.</summary>
    private void Stream()
    {
        CancellationToken cancelToken = _cts.Token;
        try
        {
            foreach (ObolTraceEvent traceEvent in _events.GetConsumingEnumerable(cancelToken))
            {
                WriteObject(traceEvent);
            }
        }
        catch (OperationCanceledException) when (cancelToken.IsCancellationRequested)
        {
            // Ctrl+C or Select-Object -First ended the trace.
        }
    }

    /// <summary>
    /// Runs the scriptblock in the caller's scope and then writes the events raised while it ran. The events are
    /// written even if the scriptblock fails, before its error, so a failed test still shows what the KDC saw.
    /// </summary>
    private void Capture(ScriptBlock scriptBlock)
    {
        try
        {
            ScriptBlockHelper.Invoke(this, scriptBlock, [.. _kdcs], dotSource: true, discardOutput: true);
        }
        catch (Exception e) when (e is not PipelineStoppedException)
        {
            WriteCaptured();
            throw;
        }

        WriteCaptured();
    }

    private void WriteCaptured()
    {
        // The events were raised before each reply was sent, so a request a client in the scriptblock waited for
        // is already queued when the scriptblock returns.
        _events.CompleteAdding();
        foreach (ObolTraceEvent traceEvent in _events.GetConsumingEnumerable())
        {
            WriteObject(traceEvent);
        }
    }

    private void OnEvent(object? sender, ObolTraceEvent traceEvent)
    {
        try
        {
            _events.Add(traceEvent);
        }
        catch (InvalidOperationException)
        {
            // The trace has finished taking events.
        }
    }

    private void OnStopped(object? sender, EventArgs e)
    {
        if (_kdcs.All(k => k.State != ObolKdcState.Running))
        {
            try
            {
                _events.CompleteAdding();
            }
            catch (ObjectDisposedException)
            {
                // The cmdlet already finished.
            }
        }
    }
}
