using System.Collections.Generic;
using System.Threading;

namespace Obol;

/// <summary>
/// Tracks the KDC pins made in this process, per thread, the only way to list them as LSASS has no read-back.
/// </summary>
/// <remarks>
/// A pin is tied to the OS thread that created it (KerbPinKdc is keyed on the thread), so the record is thread local
/// rather than process wide: <see cref="Pins"/> returns the pins for the calling thread only. A runspace driven
/// through <c>System.Management.Automation.PowerShell</c> can move between threads depending on its
/// <c>PSThreadOptions</c>, which also moves which pins apply, so the record follows the thread rather than hiding it.
/// <c>Clear-ObolSspiKdc</c> sends the process wide KerbUnpinAllKdcs, so <see cref="Clear"/> empties every thread's
/// record to match.
/// </remarks>
internal static class SspiPinRegistry
{
    private static readonly ThreadLocal<List<ObolSspiKdc>> s_pins = new(() => [], trackAllValues: true);
    private static readonly object s_lock = new();

    /// <summary>Records a pin against the calling thread and returns it.</summary>
    public static ObolSspiKdc Add(ObolSspiKdc pin)
    {
        lock (s_lock)
        {
            s_pins.Value!.Add(pin);
        }
        return pin;
    }

    /// <summary>A snapshot of the pins the calling thread made.</summary>
    public static IReadOnlyList<ObolSspiKdc> Pins
    {
        get
        {
            lock (s_lock)
            {
                return [.. s_pins.Value!];
            }
        }
    }

    /// <summary>Forgets every recorded pin on every thread, matching the process wide unpin-all.</summary>
    public static void Clear()
    {
        lock (s_lock)
        {
            foreach (List<ObolSspiKdc> list in s_pins.Values)
            {
                list.Clear();
            }
        }
    }
}
