using System.Collections.Generic;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Runtime.Versioning;

namespace Obol;

/// <summary>
/// The KDCs registered with the Windows Kerberos SSP by Enter-ObolSspiEnvironment, at most one is entered in the
/// process.
/// </summary>
/// <remarks>
/// The SSP cannot remove the entry of a single realm, so exiting removes every pin in the process for
/// <see cref="ObolSspiKdcScope.Thread"/> or purges the whole binding cache for the machine wide scopes. Only one can be
/// entered so one exit does not remove the entries another relies on.
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class SspiEnvironment
{
    private static readonly object s_lock = new();
    private static SspiEnvironment? s_current;

    private readonly SspiMachineSetup? _setup;

    private SspiEnvironment(ObolSspiKdcScope scope, string[] realms, Runspace? runspace, SspiMachineSetup? setup)
    {
        Scope = scope;
        Realms = realms;
        Runspace = runspace;
        _setup = setup;
    }

    /// <summary>How the KDCs were registered with the SSP.</summary>
    public ObolSspiKdcScope Scope { get; }

    /// <summary>The realms that were registered.</summary>
    public IReadOnlyList<string> Realms { get; }

    /// <summary>The runspace that entered the environment, it is exited when this runspace closes.</summary>
    public Runspace? Runspace { get; }

    /// <summary>The prompt of <see cref="Runspace"/> with the realms added, null if it was not changed.</summary>
    /// <remarks>Restored from the pipeline thread of the runspace, or deactivated when the runspace closes.</remarks>
    public Commands.EnvironmentPrompt.Handle? Prompt { get; set; }

    /// <summary>The environment entered in the process, or null if none is.</summary>
    public static SspiEnvironment? Current
    {
        get
        {
            lock (s_lock)
            {
                return s_current;
            }
        }
    }

    /// <summary>Whether a scope is machine wide, it needs administrator rights and purges the binding cache.</summary>
    public static bool IsMachineScope(ObolSspiKdcScope scope)
        => scope is ObolSspiKdcScope.Machine or ObolSspiKdcScope.MitRealm or ObolSspiKdcScope.DcLocator;

    /// <summary>Registers each KDC with the SSP and makes it the entered environment.</summary>
    /// <param name="scope">How to register the KDCs, see <see cref="ObolSspiKdcScope"/>.</param>
    /// <param name="kdcs">Each KDC with its realm, the address clients use and its transports.</param>
    /// <param name="runspace">Exits the environment when this runspace closes.</param>
    /// <returns>The entered environment, or null if one is already entered and nothing is changed.</returns>
    /// <exception cref="SspiKdcException">A KDC could not be registered, the ones added are removed.</exception>
    /// <exception cref="SspiConflictException">
    /// The scope would change existing Windows configuration, nothing is changed.
    /// </exception>
    public static SspiEnvironment? TryEnter(
        ObolSspiKdcScope scope,
        IReadOnlyList<(ObolKdc Kdc, string Realm, IPAddress Address, ObolKdcTransport Transport)> kdcs,
        Runspace? runspace)
    {
        lock (s_lock)
        {
            if (s_current is not null)
            {
                return null;
            }

            SspiMachineSetup? setup = Register(scope, kdcs);

            string[] realms = new string[kdcs.Count];
            for (int i = 0; i < kdcs.Count; i++)
            {
                realms[i] = kdcs[i].Realm;
            }
            s_current = new(scope, realms, runspace, setup);
            if (runspace is not null)
            {
                runspace.StateChanged += OnRunspaceStateChanged;
            }
            return s_current;
        }
    }

    /// <summary>
    /// Removes the KDCs from the SSP, every pin in the process or the whole binding cache and the configuration the
    /// scope created.
    /// </summary>
    /// <returns>False if the environment is no longer entered, such as when its runspace closed.</returns>
    /// <exception cref="SspiKdcException">
    /// The SSP entries could not be removed, the environment is still exited so another can be entered.
    /// </exception>
    public bool Exit()
    {
        lock (s_lock)
        {
            if (s_current != this)
            {
                return false;
            }
            s_current = null;

            if (Runspace is not null)
            {
                Runspace.StateChanged -= OnRunspaceStateChanged;
            }
            Unregister(Scope, _setup);
        }

        return true;
    }

    private static SspiMachineSetup? Register(
        ObolSspiKdcScope scope,
        IReadOnlyList<(ObolKdc Kdc, string Realm, IPAddress Address, ObolKdcTransport Transport)> kdcs)
    {
        SspiMachineSetup? setup = null;
        try
        {
            if (scope == ObolSspiKdcScope.Thread)
            {
                foreach ((_, string realm, IPAddress address, _) in kdcs)
                {
                    SspiKdc.PinKdc(realm, address.ToString(), (int)ObolSspiDcFlags.None);
                    SspiPinRegistry.Add(ObolSspiKdc.ForThread(realm, address.ToString(), ObolSspiDcFlags.None));
                }
            }
            else if (scope == ObolSspiKdcScope.Machine)
            {
                // Adding a binding for a realm replaces any existing one.
                using (SystemImpersonation.Acquire())
                {
                    foreach ((_, string realm, IPAddress address, _) in kdcs)
                    {
                        SspiKdc.AddBinding(realm, address.ToString(), (int)ObolSspiKdcAddressType.Inet,
                            (int)ObolSspiDcFlags.None);
                    }
                }
            }
            else
            {
                // Removes what it created itself if it fails.
                setup = SspiMachineSetup.Apply(scope, kdcs);

                // The binding cache is checked before the realm list and the DC locator, and also keeps failed
                // lookups, so an entry for the realm from before would be used instead.
                using (SystemImpersonation.Acquire())
                {
                    SspiKdc.PurgeBindings();
                }
            }
        }
        catch (SspiKdcException)
        {
            try
            {
                Unregister(scope, setup);
            }
            catch (SspiKdcException)
            {
                // The original failure is the one to report.
            }
            throw;
        }

        return setup;
    }

    private static void Unregister(ObolSspiKdcScope scope, SspiMachineSetup? setup)
    {
        if (scope == ObolSspiKdcScope.Thread)
        {
            SspiKdc.UnpinAllKdcs();
            SspiPinRegistry.Clear();
            return;
        }

        SspiKdcException? setupError = null;
        try
        {
            setup?.Remove();
        }
        catch (SspiKdcException e)
        {
            setupError = e;
        }

        // A KDC found through the realm list or the DC locator is also written to the binding cache.
        using (SystemImpersonation.Acquire())
        {
            SspiKdc.PurgeBindings();
        }

        if (setupError is not null)
        {
            throw setupError;
        }
    }

    private static void OnRunspaceStateChanged(object? sender, RunspaceStateEventArgs e)
    {
        if (e.RunspaceStateInfo.State is RunspaceState.Closing or RunspaceState.Closed or RunspaceState.Broken)
        {
            // Only the runspace that entered the current environment is subscribed.
            try
            {
                SspiEnvironment? current = Current;
                current?.Prompt?.Deactivate();
                current?.Exit();
            }
            catch (SspiKdcException)
            {
                // Nothing can report it while the runspace closes, the entries stay until they age out or a reboot.
            }
        }
    }
}
