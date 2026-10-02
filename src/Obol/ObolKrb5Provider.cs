namespace Obol;

/// <summary>The Kerberos implementation a krb5.conf is created for.</summary>
public enum ObolKrb5Provider
{
    /// <summary>The usual implementation of the current platform, Heimdal on macOS and MIT krb5 elsewhere.</summary>
    Default = 0,

    /// <summary>MIT krb5, used by most Linux distributions and MIT Kerberos for Windows.</summary>
    Mit = 1,

    /// <summary>Heimdal, including the macOS GSS framework.</summary>
    Heimdal = 2,
}
