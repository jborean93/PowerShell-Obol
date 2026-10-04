using System.Collections.Generic;
using System.Management.Automation.Runspaces;
using System.Runtime.Versioning;

namespace Obol;

/// <summary>
/// The KDCs registered with the Windows Kerberos SSP by Enter-ObolSspiEnvironment, at most one is entered in the
/// process.
/// </summary>
/// <remarks>
/// The SSP cannot remove the entry of a single realm, so exiting removes every pin in the process for
/// <see cref="ObolSspiKdcScope.Thread"/> or purges the whole binding cache for <see cref="ObolSspiKdcScope.Machine"/>.
/// Only one can be entered so one exit does not remove the entries another relies on.
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class SspiEnvironment
{
    private static readonly object s_lock = new();
    private static SspiEnvironment? s_current;

    private SspiEnvironment(ObolSspiKdcScope scope, string[] realms, Runspace? runspace)
    {
        Scope = scope;
        Realms = realms;
        Runspace = runspace;
    }

    /// <summary>Whether the KDCs are pinned for a thread or in the machine binding cache.</summary>
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

    /// <summary>Registers each KDC with the SSP and makes it the entered environment.</summary>
    /// <param name="scope">Thread pins the KDCs for the calling thread, Machine adds them to the binding cache.</param>
    /// <param name="kdcs">The realm and address of each KDC, the address is a bare host or IP.</param>
    /// <param name="runspace">Exits the environment when this runspace closes.</param>
    /// <returns>The entered environment, or null if one is already entered and nothing is changed.</returns>
    /// <exception cref="SspiKdcException">A KDC could not be registered, the ones added are removed.</exception>
    public static SspiEnvironment? TryEnter(
        ObolSspiKdcScope scope,
        IReadOnlyList<(string Realm, string Address)> kdcs,
        Runspace? runspace)
    {
        lock (s_lock)
        {
            if (s_current is not null)
            {
                return null;
            }

            try
            {
                Register(scope, kdcs);
            }
            catch (SspiKdcException)
            {
                try
                {
                    Unregister(scope);
                }
                catch (SspiKdcException)
                {
                    // The original failure is the one to report.
                }
                throw;
            }

            string[] realms = new string[kdcs.Count];
            for (int i = 0; i < kdcs.Count; i++)
            {
                realms[i] = kdcs[i].Realm;
            }
            s_current = new(scope, realms, runspace);
            if (runspace is not null)
            {
                runspace.StateChanged += OnRunspaceStateChanged;
            }
            return s_current;
        }
    }

    /// <summary>Removes the KDCs from the SSP, every pin in the process or the whole binding cache.</summary>
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

            Unregister(Scope);
        }

        return true;
    }

    private static void Register(ObolSspiKdcScope scope, IReadOnlyList<(string Realm, string Address)> kdcs)
    {
        if (scope == ObolSspiKdcScope.Machine)
        {
            // Adding a binding for a realm replaces any existing one.
            using (SystemImpersonation.Acquire())
            {
                foreach ((string realm, string address) in kdcs)
                {
                    SspiKdc.AddBinding(realm, address, (int)ObolSspiKdcAddressType.Inet, (int)ObolSspiDcFlags.None);
                }
            }
        }
        else
        {
            foreach ((string realm, string address) in kdcs)
            {
                SspiKdc.PinKdc(realm, address, (int)ObolSspiDcFlags.None);
                SspiPinRegistry.Add(ObolSspiKdc.ForThread(realm, address, ObolSspiDcFlags.None));
            }
        }
    }

    private static void Unregister(ObolSspiKdcScope scope)
    {
        if (scope == ObolSspiKdcScope.Machine)
        {
            using (SystemImpersonation.Acquire())
            {
                SspiKdc.PurgeBindings();
            }
        }
        else
        {
            SspiKdc.UnpinAllKdcs();
            SspiPinRegistry.Clear();
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
                // Nothing can report it while the runspace closes, the entries stay until they age out.
            }
        }
    }
}
