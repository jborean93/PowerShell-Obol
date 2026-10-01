using System.Collections.Generic;
using System.Management.Automation.Runspaces;

namespace Obol;

/// <summary>
/// Stores the module-specific state for the current runspace.
/// </summary>
internal sealed class ModuleSettings
{
    private static readonly RunspaceSpecificStorage<ModuleSettings> s_state = new(() => new());

    private readonly List<ObolKdc> _kdcs = [];

    private ModuleSettings() { }

    /// <summary>The KDCs started by Start-ObolKdc in the runspace that are still running, oldest first.</summary>
    public ObolKdc[] Kdcs
    {
        get
        {
            // KDCs are removed from the thread closing the runspace, not only the pipeline thread.
            lock (_kdcs)
            {
                return _kdcs.ToArray();
            }
        }
    }

    public static ModuleSettings GetFromTLS() => s_state.GetFromTLS();

    public static ModuleSettings GetForRunspace(Runspace runspace) => s_state.GetForRunspace(runspace);

    public void AddKdc(ObolKdc kdc)
    {
        lock (_kdcs)
        {
            _kdcs.Add(kdc);
        }
    }

    public void RemoveKdc(ObolKdc kdc)
    {
        lock (_kdcs)
        {
            _kdcs.Remove(kdc);
        }
    }
}
