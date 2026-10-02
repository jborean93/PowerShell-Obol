using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using Obol.Protocol;

namespace Obol.Commands;

/// <summary>Collects the principals and entries for Export-ObolKeytab and ConvertTo-ObolKeytab.</summary>
internal sealed class KeytabBuilder
{
    private readonly List<ObolPrincipal> _principals = [];
    private readonly HashSet<ObolPrincipal> _seen = [];
    private readonly List<ObolKeytabEntry> _entries = [];

    /// <summary>Whether no principal or entry was added.</summary>
    public bool IsEmpty => _principals.Count == 0 && _entries.Count == 0;

    /// <summary>The names of what was added for ShouldProcess messages.</summary>
    public string Names => _principals.Count > 0
        ? string.Join(", ", _principals)
        : string.Join(", ", _entries.Select(e => e.FullName).Distinct());

    /// <summary>Adds principals, a principal added more than once is only written once.</summary>
    public void Add(IEnumerable<ObolPrincipal> principals)
    {
        foreach (ObolPrincipal principal in principals)
        {
            if (_seen.Add(principal))
            {
                _principals.Add(principal);
            }
        }
    }

    /// <summary>Adds entries, they are written as given, including duplicates and unsupported types.</summary>
    public void Add(IEnumerable<ObolKeytabEntry> entries)
    {
        // A null in an array from the pipeline or a variable is not checked by the parameter validation.
        _entries.AddRange(entries.Where(e => e is not null));
    }

    /// <summary>Writes the entries of the principals followed by the added entries, without the file header.</summary>
    public void Write(IBufferWriter<byte> writer)
    {
        DateTime now = DateTime.UtcNow;
        foreach (ObolPrincipal principal in _principals)
        {
            foreach (ObolKeytabEntry entry in Keytab.GetEntries(principal, now))
            {
                Keytab.WriteEntry(writer, entry);
            }
        }
        foreach (ObolKeytabEntry entry in _entries)
        {
            Keytab.WriteEntry(writer, entry);
        }
    }
}
