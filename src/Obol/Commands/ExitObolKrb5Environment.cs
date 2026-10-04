using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.Exit, "ObolKrb5Environment",
    SupportsShouldProcess = true
)]
public sealed class ExitObolKrb5Environment : PSCmdlet
{
    protected override void EndProcessing()
    {
        if (Krb5Environment.Current is not Krb5Environment environment)
        {
            WriteVerbose("No krb5 environment is entered");
            return;
        }

        // The prompt can only be restored from the runspace that changed it.
        if (environment.Runspace != Runspace.DefaultRunspace)
        {
            string owner = environment.Runspace is null ? "no runspace" : $"runspace {environment.Runspace.Id}";
            ThrowTerminatingError(new ErrorRecord(
                new InvalidOperationException(
                    $"The krb5 environment was entered by {owner}, it can only be exited from there"),
                "Krb5EnvironmentNotOwned",
                ErrorCategory.PermissionDenied,
                null));
        }

        if (!ShouldProcess("process environment", "Restore the krb5 environment variables"))
        {
            return;
        }

        Exit(this, environment);
    }

    /// <summary>Restores the prompt and environment variables and removes the files of the environment.</summary>
    /// <remarks>Must be called from the runspace that entered it, a failure to remove the files is written.</remarks>
    internal static void Exit(PSCmdlet cmdlet, Krb5Environment environment)
    {
        if (environment.Prompt is { } prompt)
        {
            EnvironmentPrompt.Restore(cmdlet, prompt);
            environment.Prompt = null;
        }

        if (!environment.Exit())
        {
            return;
        }

        try
        {
            environment.RemoveDirectory();
            cmdlet.WriteVerbose($"Exited the krb5 environment in '{environment.Directory}'");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // The variables are restored, only the files are left behind.
            cmdlet.WriteError(new ErrorRecord(
                e,
                "Krb5EnvironmentRemoveFailed",
                ErrorCategory.WriteError,
                environment.Directory)
            {
                ErrorDetails = new("The krb5 environment variables were restored but the directory " +
                    $"'{environment.Directory}' could not be removed: {e.Message}"),
            });
        }
    }
}
