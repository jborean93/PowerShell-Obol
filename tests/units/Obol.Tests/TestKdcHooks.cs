using System;
using System.Collections.Concurrent;
using System.Linq;

namespace Obol.Tests;

/// <summary>Fails a test whose <see cref="TestKdc"/> listener faulted, even if the test itself passed.</summary>
public static class TestKdcHooks
{
    /// <summary>The <see cref="TestContext.StateBag"/> key of the KDCs created by the test.</summary>
    internal const string StateBagKey = "Obol.Tests.TestKdc";

    [AfterEvery(HookType.Test)]
    public static void FailOnListenerFault(TestContext context)
    {
        if (!context.StateBag.TryGetValue(StateBagKey, out ConcurrentQueue<TestKdc>? kdcs) || kdcs is null)
        {
            return;
        }

        Exception[] faults = [.. kdcs.Select(k => k.Fault).OfType<Exception>()];

        // A test that already failed keeps its own failure, the fault is likely a result of it.
        if (faults.Length == 0 || context.Execution.Result?.State == TestState.Failed)
        {
            return;
        }

        throw new AggregateException("The KDC listener faulted during the test", faults);
    }
}
