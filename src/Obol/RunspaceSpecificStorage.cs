using System;
using System.Management.Automation.Runspaces;
using System.Runtime.CompilerServices;
using System.Threading;

namespace Obol;

/// <summary>Stores a value per runspace, created on first use and released with the runspace.</summary>
internal sealed class RunspaceSpecificStorage<T>
{
    private readonly ConditionalWeakTable<Runspace, Lazy<T>> _map = [];

    private readonly Func<T> _factory;

    private readonly LazyThreadSafetyMode _mode = LazyThreadSafetyMode.ExecutionAndPublication;

    private readonly Lazy<T> _noRunspace;

    public RunspaceSpecificStorage(Func<T> factory)
    {
        _factory = factory;
        _noRunspace = new Lazy<T>(() => _factory(), _mode);
    }

    /// <summary>Gets the value for the runspace of the current thread.</summary>
    /// <remarks>
    /// A thread with no default runspace, such as a host opening a runspace from a thread pool thread, shares a
    /// single instance.
    /// </remarks>
    public T GetFromTLS()
    {
        Runspace? runspace = Runspace.DefaultRunspace;
        return runspace is null ? _noRunspace.Value : GetForRunspace(runspace);
    }

    public T GetForRunspace(Runspace runspace)
    {
        return _map.GetValue(
            runspace,
            _ => new Lazy<T>(() => _factory(), _mode))
            .Value;
    }
}
