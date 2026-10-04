namespace Obol;

/// <summary>Where a Windows SSPI KDC steering entry applies.</summary>
public enum ObolSspiKdcScope
{
    /// <summary>The current OS thread only (a <c>KerbPinKdc</c> pin), no administrator rights needed.</summary>
    Thread,

    /// <summary>The whole process, every thread. Used by <c>Clear-ObolSspiKdc</c> to unpin all threads at once.</summary>
    Process,

    /// <summary>The whole machine (the binding cache), shared by every process. Needs administrator rights.</summary>
    Machine,
}
