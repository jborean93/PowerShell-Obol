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

    /// <summary>
    /// The whole machine through the static realm KDC list (<c>ksetup /addkdc</c>), the realm is an MIT realm. Needs
    /// administrator rights.
    /// </summary>
    MitRealm,

    /// <summary>
    /// The whole machine through the AD DC locator, an NRPT rule sends the realm's DNS queries to a DNS server and
    /// CLDAP responder Obol runs. Needs administrator rights.
    /// </summary>
    DcLocator,
}
