using System;

namespace Obol;

/// <summary>
/// Thrown when an SSPI environment would change Windows configuration that already exists, such as a realm added with
/// ksetup or an NRPT rule for the realm.
/// </summary>
internal sealed class SspiConflictException : Exception
{
    public SspiConflictException(string message)
        : base(message)
    {
    }
}
