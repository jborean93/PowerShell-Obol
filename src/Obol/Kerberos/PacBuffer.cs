namespace Obol.Kerberos;

/// <summary>A buffer of a PAC, MS-PAC 2.4, with its raw bytes.</summary>
public sealed class PacBuffer
{
    internal PacBuffer(PacBufferType type, byte[] data)
    {
        Type = type;
        Data = data;
    }

    /// <summary>The ulType, a type without a name is shown as its number.</summary>
    public PacBufferType Type { get; }

    /// <summary>The bytes of the buffer.</summary>
    public byte[] Data { get; }

    public override string ToString() => $"{Type}, {Data.Length} bytes";
}
