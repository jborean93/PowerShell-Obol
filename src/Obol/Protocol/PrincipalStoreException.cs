using System;

namespace Obol.Protocol;

/// <summary>A change to the principal store was rejected, see <see cref="Error"/> for why.</summary>
internal sealed class PrincipalStoreException : Exception
{
    public PrincipalStoreException(PrincipalStoreError error, string message)
        : base(message)
    {
        Error = error;
    }

    public PrincipalStoreError Error { get; }
}
