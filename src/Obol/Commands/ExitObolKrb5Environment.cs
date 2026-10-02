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

        if (environment.Prompt is { } prompt)
        {
            Krb5EnvironmentPrompt.Restore(this, prompt);
            environment.Prompt = null;
        }

        if (!environment.Exit())
        {
            return;
        }

        try
        {
            environment.RemoveDirectory();
            WriteVerbose($"Exited the krb5 environment in '{environment.Directory}'");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // The variables are restored, only the files are left behind.
            WriteError(new ErrorRecord(
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
