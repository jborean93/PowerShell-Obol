using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Kerberos.NET.Crypto;
using Obol.Kerberos;
using EncryptionType = Obol.Kerberos.EncryptionType;

namespace Obol.Protocol;

/// <summary>Reads and writes keys in the MIT keytab file format, version 0x0502.</summary>
/// <remarks>
/// The format is described in the MIT krb5 documentation "Keytab file format". Every number is big endian and each
/// entry is its length followed by the principal, timestamp, 8-bit kvno, key and 32-bit kvno.
/// </remarks>
internal static class Keytab
{
    /// <summary>The file version, the first 2 bytes of a keytab.</summary>
    public static ReadOnlySpan<byte> Header => [0x05, 0x02];


    /// <summary>The keytab entries of a principal, one for each key under its name and each of its aliases.</summary>
    /// <param name="principal">The principal to get the keys of.</param>
    /// <param name="timestamp">The time to record as when the keys were written.</param>
    public static List<ObolKeytabEntry> GetEntries(ObolPrincipal principal, DateTime timestamp)
    {
        // Read the state once so the names and keys are from the same version of the principal.
        PrincipalState state = principal.State;
        List<string[]> names = [principal.Components];
        foreach (string alias in state.Aliases)
        {
            // Aliases are stored escaped without a realm so they always parse.
            PrincipalName.TryParse(alias, out string[]? components, out _, out _);
            names.Add(components!);
        }

        List<ObolKeytabEntry> entries = [];
        foreach (string[] components in names)
        {
            foreach (KerberosKey key in state.Keys)
            {
                entries.Add(new ObolKeytabEntry(
                    principal.Realm,
                    components,
                    PrincipalNameType.Principal,
                    timestamp,
                    state.Kvno,
                    key.EncryptionType.ToObol(),
                    key.GetKey().ToArray()));
            }
        }
        return entries;
    }

    /// <summary>Reads the entries of a keytab file.</summary>
    /// <remarks>
    /// Deleted entries, a negative length, are skipped and bytes after the 32-bit kvno of an entry are ignored. The
    /// 8-bit kvno is used when the 32-bit kvno is missing or 0, like MIT. Version 0x0501 keytabs use the byte order
    /// of the host that wrote them and are not supported.
    /// </remarks>
    /// <exception cref="InvalidDataException">The data is not a valid keytab.</exception>
    public static List<ObolKeytabEntry> Read(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2 || !data[..2].SequenceEqual(Header))
        {
            string version = data.Length < 2 ? "none" : $"0x{BinaryPrimitives.ReadUInt16BigEndian(data):X4}";
            throw new InvalidDataException(
                $"The data is not a keytab of version 0x0502, the version is {version}");
        }

        List<ObolKeytabEntry> entries = [];
        int offset = 2;
        while (offset < data.Length)
        {
            if (data.Length - offset < 4)
            {
                throw new InvalidDataException($"The entry length at offset {offset} is truncated");
            }

            int length = BinaryPrimitives.ReadInt32BigEndian(data[offset..]);
            offset += 4;
            if (length == int.MinValue || Math.Abs(length) > data.Length - offset)
            {
                throw new InvalidDataException(
                    $"The entry at offset {offset - 4} has a length of {length} which is past the end of the data");
            }

            if (length > 0)
            {
                entries.Add(ReadEntry(data.Slice(offset, length), offset));
            }

            // A negative length is a deleted entry, a hole MIT can reuse for a new entry of the same size.
            offset += Math.Abs(length);
        }

        return entries;
    }

    private static ObolKeytabEntry ReadEntry(ReadOnlySpan<byte> entry, int entryOffset)
    {
        int offset = 0;
        try
        {
            int count = ReadUInt16(entry, ref offset);
            string realm = ReadString(entry, ref offset);
            string[] components = new string[count];
            for (int i = 0; i < count; i++)
            {
                components[i] = ReadString(entry, ref offset);
            }

            // Stored unsigned, the MS-KILE types are negative so the bits are kept as an int.
            PrincipalNameType nameType = (PrincipalNameType)unchecked((int)ReadUInt32(entry, ref offset));
            uint timestamp = ReadUInt32(entry, ref offset);
            int kvno = entry[offset++];
            int etype = ReadUInt16(entry, ref offset);
            int keyLength = ReadUInt16(entry, ref offset);
            byte[] key = entry.Slice(offset, keyLength).ToArray();
            offset += keyLength;

            if (entry.Length - offset >= 4)
            {
                uint kvno32 = ReadUInt32(entry, ref offset);
                if (kvno32 != 0)
                {
                    if (kvno32 > int.MaxValue)
                    {
                        throw new InvalidDataException(
                            $"The entry at offset {entryOffset} has a kvno of {kvno32} which is too large");
                    }
                    kvno = (int)kvno32;
                }
            }

            if (count == 0)
            {
                throw new InvalidDataException($"The entry at offset {entryOffset} has no name components");
            }

            return new ObolKeytabEntry(
                realm,
                components,
                nameType,
                DateTime.UnixEpoch.AddSeconds(timestamp),
                kvno,
                (EncryptionType)etype,
                key);
        }
        catch (ArgumentOutOfRangeException)
        {
            throw new InvalidDataException($"The entry at offset {entryOffset} is truncated");
        }
        catch (IndexOutOfRangeException)
        {
            throw new InvalidDataException($"The entry at offset {entryOffset} is truncated");
        }
    }

    private static string ReadString(ReadOnlySpan<byte> buffer, ref int offset)
    {
        int length = ReadUInt16(buffer, ref offset);
        string value = Encoding.UTF8.GetString(buffer.Slice(offset, length));
        offset += length;
        return value;
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> buffer, ref int offset)
    {
        ushort value = BinaryPrimitives.ReadUInt16BigEndian(buffer[offset..]);
        offset += 2;
        return value;
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> buffer, ref int offset)
    {
        uint value = BinaryPrimitives.ReadUInt32BigEndian(buffer[offset..]);
        offset += 4;
        return value;
    }

    /// <summary>Writes a keytab entry as it is, including keys of encryption types Obol does not support.</summary>
    /// <param name="writer">The buffer to write the entry to.</param>
    /// <param name="entry">The entry to write, its timestamp is clamped to the 32-bit range of the format.</param>
    public static void WriteEntry(IBufferWriter<byte> writer, ObolKeytabEntry entry)
    {
        long seconds = new DateTimeOffset(entry.Timestamp.ToUniversalTime()).ToUnixTimeSeconds();
        WriteEntry(
            writer,
            entry.Realm,
            entry.Components,
            unchecked((uint)(int)entry.NameType),
            (uint)Math.Clamp(seconds, 0, uint.MaxValue),
            entry.Kvno,
            (ushort)entry.EncryptionType,
            entry.Key);
    }

    private static void WriteEntry(
        IBufferWriter<byte> writer,
        string realm,
        string[] components,
        uint nameType,
        uint time,
        int kvno,
        ushort etype,
        ReadOnlySpan<byte> key)
    {
        int length = 2 + GetStringLength(realm);
        foreach (string component in components)
        {
            length += GetStringLength(component);
        }
        length += 4 + 4 + 1 + 2 + 2 + key.Length + 4;

        Span<byte> entry = writer.GetSpan(4 + length)[..(4 + length)];
        int offset = 0;
        WriteInt32(entry, ref offset, length);
        WriteUInt16(entry, ref offset, checked((ushort)components.Length));
        WriteString(entry, ref offset, realm);
        foreach (string component in components)
        {
            WriteString(entry, ref offset, component);
        }
        WriteUInt32(entry, ref offset, nameType);
        WriteUInt32(entry, ref offset, time);
        entry[offset++] = unchecked((byte)kvno);
        WriteUInt16(entry, ref offset, etype);
        WriteUInt16(entry, ref offset, checked((ushort)key.Length));
        key.CopyTo(entry[offset..]);
        offset += key.Length;

        // The 8-bit kvno above only holds the low byte, readers use this one when it is present.
        WriteUInt32(entry, ref offset, (uint)kvno);
        writer.Advance(offset);
    }

    private static int GetStringLength(string value)
    {
        int length = Encoding.UTF8.GetByteCount(value);
        if (length > ushort.MaxValue)
        {
            throw new ArgumentException($"The name component of {length} bytes is too long for a keytab");
        }
        return 2 + length;
    }

    private static void WriteString(Span<byte> buffer, ref int offset, string value)
    {
        int length = Encoding.UTF8.GetBytes(value, buffer[(offset + 2)..]);
        WriteUInt16(buffer, ref offset, (ushort)length);
        offset += length;
    }

    private static void WriteUInt16(Span<byte> buffer, ref int offset, ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(buffer[offset..], value);
        offset += 2;
    }

    private static void WriteInt32(Span<byte> buffer, ref int offset, int value)
    {
        BinaryPrimitives.WriteInt32BigEndian(buffer[offset..], value);
        offset += 4;
    }

    private static void WriteUInt32(Span<byte> buffer, ref int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], value);
        offset += 4;
    }
}
