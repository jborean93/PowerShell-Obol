namespace Obol;

/// <summary>The state of an <see cref="ObolKdc"/>.</summary>
public enum ObolKdcState
{
    /// <summary>The KDC is listening for requests.</summary>
    Running,

    /// <summary>The KDC has been stopped and no longer accepts requests.</summary>
    Stopped,

    /// <summary>The KDC stopped because of an unexpected error, see <see cref="ObolKdc.Error"/>.</summary>
    Faulted,
}
