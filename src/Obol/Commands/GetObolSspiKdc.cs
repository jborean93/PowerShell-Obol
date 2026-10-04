using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace Obol.Commands;

[Cmdlet(VerbsCommon.Get, "ObolSspiKdc")]
[OutputType(typeof(ObolSspiKdc))]
public sealed class GetObolSspiKdc : PSCmdlet
{
    [Parameter]
    [ValidateSet("Thread", "Machine")]
    public ObolSspiKdcScope Scope { get; set; } = ObolSspiKdcScope.Thread;

    protected override void EndProcessing()
    {
        if (!OperatingSystem.IsWindows())
        {
            ThrowTerminatingError(SspiCommandHelper.NotWindowsError("Get-ObolSspiKdc"));
            return;
        }

        if (Scope == ObolSspiKdcScope.Machine)
        {
            List<ObolSspiKdc> bindings;
            try
            {
                using (SystemImpersonation.Acquire())
                {
                    bindings = SspiKdc.QueryBindings();
                }
            }
            catch (SspiKdcException e)
            {
                ThrowTerminatingError(SspiCommandHelper.SspiError(e));
                return;
            }

            WriteObject(bindings, enumerateCollection: true);
        }
        else
        {
            // Thread scope: Obol's record for the calling thread, LSASS has no read-back.
            WriteObject(SspiPinRegistry.Pins, enumerateCollection: true);
        }
    }
}
