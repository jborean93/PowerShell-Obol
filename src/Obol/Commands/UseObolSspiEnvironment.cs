using System;
using System.Management.Automation;

namespace Obol.Commands;

[Cmdlet(
    VerbsOther.Use, "ObolSspiEnvironment",
    DefaultParameterSetName = StartParameterSet
)]
public sealed class UseObolSspiEnvironment : UseObolEnvironmentCommandBase
{
    [Parameter]
    [ValidateSet("Thread", "Machine")]
    public ObolSspiKdcScope Scope { get; set; } = ObolSspiKdcScope.Thread;

    /// <summary>The SSP only uses port 88, so the KDC always listens on it.</summary>
    protected override int StartPort => SspiCommandHelper.KdcPort;

    protected override void BeginProcessing()
    {
        if (!OperatingSystem.IsWindows())
        {
            ThrowTerminatingError(SspiCommandHelper.NotWindowsError("Use-ObolSspiEnvironment"));
            return;
        }

        EnterObolSspiEnvironment.CheckCanEnter(this, Scope);
    }

    protected override ErrorRecord? CheckKdc(ObolKdc kdc) => SspiCommandHelper.CheckKdc(kdc);

    protected override void InvokeWithKdcs(ScriptBlock scriptBlock)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // The prompt is not shown while the scriptblock runs, so it is left alone.
        SspiEnvironment environment = EnterObolSspiEnvironment.Enter(this, Kdcs, Scope, setPrompt: false);
        try
        {
            Invoke(scriptBlock);
        }
        finally
        {
            ExitObolSspiEnvironment.Exit(this, environment);
        }
    }
}
