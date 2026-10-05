using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Runtime.Versioning;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.Exit, "ObolSspiEnvironment",
    SupportsShouldProcess = true
)]
public sealed class ExitObolSspiEnvironment : PSCmdlet
{
    protected override void EndProcessing()
    {
        if (!OperatingSystem.IsWindows())
        {
            ThrowTerminatingError(SspiCommandHelper.NotWindowsError("Exit-ObolSspiEnvironment"));
            return;
        }

        if (SspiEnvironment.Current is not SspiEnvironment environment)
        {
            WriteVerbose("No SSPI environment is entered");
            return;
        }

        // The prompt can only be restored from the runspace that changed it.
        if (environment.Runspace != Runspace.DefaultRunspace)
        {
            string owner = environment.Runspace is null ? "no runspace" : $"runspace {environment.Runspace.Id}";
            ThrowTerminatingError(new ErrorRecord(
                new InvalidOperationException(
                    $"The SSPI environment was entered by {owner}, it can only be exited from there"),
                "SspiEnvironmentNotOwned",
                ErrorCategory.PermissionDenied,
                null));
        }

        string action = environment.Scope switch
        {
            ObolSspiKdcScope.Machine => "Purge the whole KDC binding cache",
            ObolSspiKdcScope.MitRealm => "Remove the realm registry keys and purge the whole KDC binding cache",
            ObolSspiKdcScope.DcLocator =>
                "Remove the NRPT rules, stop the DNS and LDAP listeners and purge the whole KDC binding cache",
            _ => "Remove all KDC pins in the process",
        };
        if (!ShouldProcess($"SSPI environment for {string.Join(", ", environment.Realms)}", action))
        {
            return;
        }

        Exit(this, environment);
    }

    /// <summary>Restores the prompt and removes the KDCs of the environment from the Kerberos SSP.</summary>
    /// <remarks>Must be called from the runspace that entered it, a failure to remove the KDCs is written.</remarks>
    [SupportedOSPlatform("windows")]
    internal static void Exit(PSCmdlet cmdlet, SspiEnvironment environment)
    {
        if (environment.Prompt is { } prompt)
        {
            EnvironmentPrompt.Restore(cmdlet, prompt);
            environment.Prompt = null;
        }

        try
        {
            if (environment.Exit())
            {
                cmdlet.WriteVerbose($"Exited the SSPI environment for {string.Join(", ", environment.Realms)}");
            }
        }
        catch (SspiKdcException e)
        {
            // The environment is exited, only the SSP entries are left behind.
            cmdlet.WriteError(SspiCommandHelper.SspiError(e));
        }
    }
}
