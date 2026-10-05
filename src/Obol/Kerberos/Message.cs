namespace Obol.Kerberos;

/// <summary>A Kerberos message as sent on the wire, the base of the decoded message types.</summary>
/// <remarks>
/// A message is of this type itself, rather than a derived one, when it could not be decoded. Then
/// <see cref="MessageType"/> is <c>Unknown</c> or the type the outer tag claimed, and the exception is on the event.
/// </remarks>
public class Message
{
    internal Message(MessageType messageType, byte[] bytes)
    {
        MessageType = messageType;
        Bytes = bytes;
    }

    /// <summary>The type of the message.</summary>
    public MessageType MessageType { get; }

    /// <summary>The DER encoding of the message as sent, without the TCP length prefix.</summary>
    public byte[] Bytes { get; }

    public override string ToString() => $"{MessageType}, {Bytes.Length} bytes";
}
