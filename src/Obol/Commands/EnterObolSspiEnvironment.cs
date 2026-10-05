using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Runtime.Versioning;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.Enter, "ObolSspiEnvironment",
    SupportsShouldProcess = true
)]
public sealed class EnterObolSspiEnvironment : PSCmdlet
{
    private readonly List<ObolKdc> _kdcs = [];

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true
    )]
    [ValidateNotNull]
    public ObolKdc[] Kdc { get; set; } = [];

    [Parameter]
    [ValidateSet("Thread", "Machine", "MitRealm", "DcLocator")]
    public ObolSspiKdcScope Scope { get; set; } = ObolSspiKdcScope.Thread;

    [Parameter]
    public SwitchParameter NoPrompt { get; set; }

    protected override void BeginProcessing()
    {
        if (!OperatingSystem.IsWindows())
        {
            ThrowTerminatingError(SspiCommandHelper.NotWindowsError("Enter-ObolSspiEnvironment"));
            return;
        }

        // Checked again when entering, this avoids collecting the KDCs when it would fail anyway.
        CheckCanEnter(this, Scope);
    }

    protected override void ProcessRecord()
    {
        foreach (ObolKdc kdc in Kdc)
        {
            if (SspiCommandHelper.CheckKdc(kdc, Scope) is ErrorRecord error)
            {
                WriteError(error);
                continue;
            }
            _kdcs.Add(kdc);
        }
    }

    protected override void EndProcessing()
    {
        // Nothing is changed if every KDC failed.
        if (!OperatingSystem.IsWindows() || _kdcs.Count == 0)
        {
            return;
        }

        string target = Scope switch
        {
            ObolSspiKdcScope.Thread => "current thread",
            ObolSspiKdcScope.Machine => "machine",
            _ => $"machine as {Scope}",
        };
        if (!ShouldProcess(target, $"Register with Windows Kerberos {string.Join(", ", _kdcs)}"))
        {
            return;
        }

        Enter(this, _kdcs, Scope, setPrompt: !NoPrompt);
    }

    /// <summary>Checks an SSPI environment can be entered, before any KDC is started or collected.</summary>
    /// <remarks>
    /// Fails if one is already entered, if a machine wide scope is used without administrator rights or the rights
    /// for the binding cache, or if Thread is used while the thread already has a pin, as exiting removes every pin
    /// in the process.
    /// </remarks>
    [SupportedOSPlatform("windows")]
    internal static void CheckCanEnter(PSCmdlet cmdlet, ObolSspiKdcScope scope)
    {
        if (SspiEnvironment.Current is not null)
        {
            cmdlet.ThrowTerminatingError(AlreadyEnteredError());
        }

        if (SspiCommandHelper.CheckAdministrator(scope) is ErrorRecord adminError)
        {
            cmdlet.ThrowTerminatingError(adminError);
        }

        if (SspiEnvironment.IsMachineScope(scope))
        {
            // Acquired and released here so a caller without the rights fails before a KDC is started.
            try
            {
                using (SystemImpersonation.Acquire())
                {
                }
            }
            catch (SspiKdcException e)
            {
                cmdlet.ThrowTerminatingError(SspiCommandHelper.SspiError(e));
            }
        }
        else if (SspiPinRegistry.Pins.Count > 0)
        {
            cmdlet.ThrowTerminatingError(new ErrorRecord(
                new InvalidOperationException("A KDC is already pinned for the Kerberos SSP on this thread, use " +
                    "Clear-ObolSspiKdc to remove it first"),
                "SspiKdcAlreadyPinned",
                ErrorCategory.InvalidOperation,
                null));
        }
    }

    /// <summary>Registers each KDC with the Kerberos SSP in the scope given.</summary>
    /// <param name="cmdlet">The cmdlet to write to and throw the terminating errors of.</param>
    /// <param name="kdcs">The KDCs to register, each checked with <see cref="SspiCommandHelper.CheckKdc"/>.</param>
    /// <param name="scope">How to register the KDCs, see <see cref="ObolSspiKdcScope"/>.</param>
    /// <param name="setPrompt">Add the realm to the prompt of the current runspace.</param>
    [SupportedOSPlatform("windows")]
    internal static SspiEnvironment Enter(
        PSCmdlet cmdlet,
        IReadOnlyList<ObolKdc> kdcs,
        ObolSspiKdcScope scope,
        bool setPrompt)
    {
        // A KDC listening on all addresses is reached through loopback.
        (string, IPAddress, ObolKdcTransport)[] entries = kdcs
            .Select(k => (k.Realm, Krb5Config.GetClientAddress(k.Endpoint.Address), k.Transport))
            .ToArray();

        SspiEnvironment? environment = null;
        try
        {
            environment = SspiEnvironment.TryEnter(scope, entries, Runspace.DefaultRunspace);
        }
        catch (SspiKdcException e)
        {
            cmdlet.ThrowTerminatingError(SspiCommandHelper.SspiError(e));
        }
        catch (SspiConflictException e)
        {
            cmdlet.ThrowTerminatingError(SspiCommandHelper.ConflictError(e));
        }
        if (environment is null)
        {
            cmdlet.ThrowTerminatingError(AlreadyEnteredError());
            throw new InvalidOperationException();
        }

        cmdlet.WriteVerbose($"Entered the SSPI environment for {string.Join(", ", environment.Realms)} with " +
            $"scope {scope}");

        if (setPrompt)
        {
            // Magenta tells it apart from the cyan realm of a krb5 environment.
            string label = EnvironmentPrompt.GetLabel([.. environment.Realms]);
            environment.Prompt = EnvironmentPrompt.Set(cmdlet, label, "Magenta");
        }
        return environment;
    }

    internal static ErrorRecord AlreadyEnteredError() => new(
        new InvalidOperationException(
            "An SSPI environment is already entered in this process, run Exit-ObolSspiEnvironment first"),
        "SspiEnvironmentAlreadyEntered",
        ErrorCategory.ResourceExists,
        null);
}
