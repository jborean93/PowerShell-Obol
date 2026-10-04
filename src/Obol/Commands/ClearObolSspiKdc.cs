using System;
using System.Management.Automation;
using System.Runtime.Versioning;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.Clear, "ObolSspiKdc",
    SupportsShouldProcess = true
)]
public sealed class ClearObolSspiKdc : PSCmdlet
{
    [Parameter]
    [ValidateSet("Process", "Machine")]
    public ObolSspiKdcScope Scope { get; set; } = ObolSspiKdcScope.Process;

    protected override void EndProcessing()
    {
        if (!OperatingSystem.IsWindows())
        {
            ThrowTerminatingError(SspiCommandHelper.NotWindowsError("Clear-ObolSspiKdc"));
            return;
        }

        if (Scope == ObolSspiKdcScope.Machine)
        {
            if (!ShouldProcess("machine binding cache", "Purge all KDC binding cache entries"))
            {
                return;
            }

            try
            {
                ClearMachine();
            }
            catch (SspiKdcException e)
            {
                ThrowTerminatingError(SspiCommandHelper.SspiError(e));
            }
        }
        else
        {
            // Unpin-all is process wide, there is no per-realm or per-thread unpin.
            if (!ShouldProcess("current process", "Remove all KDC pins"))
            {
                return;
            }

            try
            {
                ClearThread();
            }
            catch (SspiKdcException e)
            {
                ThrowTerminatingError(SspiCommandHelper.SspiError(e));
            }
        }
    }

    /// <summary>Purges the whole machine binding cache as SYSTEM.</summary>
    [SupportedOSPlatform("windows")]
    private static void ClearMachine()
    {
        using (SystemImpersonation.Acquire())
        {
            SspiKdc.PurgeBindings();
        }
    }

    /// <summary>Removes every pin for the process and clears the record.</summary>
    [SupportedOSPlatform("windows")]
    private static void ClearThread()
    {
        SspiKdc.UnpinAllKdcs();
        SspiPinRegistry.Clear();
    }
}
