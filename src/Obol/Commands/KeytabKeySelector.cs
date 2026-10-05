using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using Obol.Kerberos;
using Obol.Protocol;

namespace Obol.Commands;

/// <summary>Picks the keys of a principal from keytab entries for the -Key parameters.</summary>
internal static class KeytabKeySelector
{
    /// <summary>Selects the keys of a principal from keytab entries.</summary>
    /// <remarks>
    /// Only entries for the principal name or one of its aliases in the KDC realm are used, others are ignored. An
    /// entry with an unsupported encryption type or a key of the wrong size writes a warning. The newest kvno is
    /// used unless one is given, an encryption type only found at an older kvno writes a warning.
    /// </remarks>
    /// <param name="cmdlet">The cmdlet to write warnings for.</param>
    /// <param name="entries">The keytab entries to select from.</param>
    /// <param name="store">The store of the KDC the principal belongs to, for the realm and name comparer.</param>
    /// <param name="names">The escaped names of the principal and its aliases without the realm.</param>
    /// <param name="fullName">The principal name used in messages.</param>
    /// <param name="kvno">The kvno to select, the newest if not set.</param>
    /// <param name="error">The error to write when no keys can be used.</param>
    /// <returns>The keys, or null if no keys can be used.</returns>
    public static ImportedKeys? Select(
        Cmdlet cmdlet,
        ObolKeytabEntry[] entries,
        PrincipalStore store,
        IEnumerable<string> names,
        string fullName,
        int? kvno,
        out ErrorRecord? error)
    {
        error = null;
        HashSet<string> nameSet = new(names, store.CaseInsensitive
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal);

        List<ObolKeytabEntry> usable = [];
        HashSet<(EncryptionType, int)> warned = [];
        foreach (ObolKeytabEntry entry in entries)
        {
            // A null in an array cast from a hashtable is not checked by the parameter validation.
            if (entry is null || !string.Equals(entry.Realm, store.Realm, StringComparison.Ordinal) ||
                !nameSet.Contains(entry.Name))
            {
                continue;
            }

            // Aliases repeat the same keys, only warn once for each key.
            if (!PrincipalStore.SupportedEncryptionTypes.Contains(entry.EncryptionType))
            {
                if (warned.Add((entry.EncryptionType, entry.Kvno)))
                {
                    cmdlet.WriteWarning(
                        $"Ignoring the keytab entry for {entry.FullName} with kvno {entry.Kvno}, encryption type " +
                        $"{entry.EncryptionType} is not supported");
                }
                continue;
            }

            if (entry.Key.Length != PrincipalStore.GetKeySize(entry.EncryptionType))
            {
                if (warned.Add((entry.EncryptionType, entry.Kvno)))
                {
                    cmdlet.WriteWarning(
                        $"Ignoring the keytab entry for {entry.FullName} with kvno {entry.Kvno}, the " +
                        $"{entry.EncryptionType} key is {entry.Key.Length} bytes but should be " +
                        $"{PrincipalStore.GetKeySize(entry.EncryptionType)}");
                }
                continue;
            }

            usable.Add(entry);
        }

        if (usable.Count == 0)
        {
            error = new ErrorRecord(
                new ArgumentException(
                    $"No usable keys for {fullName} were found in the keytab entries, an entry must be for the " +
                    $"principal name or an alias in the realm {store.Realm} with a supported encryption type"),
                "NoKeytabKey",
                ErrorCategory.ObjectNotFound,
                fullName);
            return null;
        }

        int selectedKvno = kvno ?? usable.Max(e => e.Kvno);
        List<ObolKeytabEntry> selected = [.. usable.Where(e => e.Kvno == selectedKvno)];
        if (selected.Count == 0)
        {
            error = new ErrorRecord(
                new ArgumentException(
                    $"No usable keys for {fullName} with kvno {selectedKvno} were found in the keytab entries, the " +
                    $"usable kvnos are {string.Join(", ", usable.Select(e => e.Kvno).Distinct().Order())}"),
                "KeytabKvnoNotFound",
                ErrorCategory.ObjectNotFound,
                fullName);
            return null;
        }

        List<(EncryptionType Type, byte[] Value)> keys = [];
        foreach (ObolKeytabEntry entry in selected)
        {
            int existing = keys.FindIndex(k => k.Type == entry.EncryptionType);
            if (existing == -1)
            {
                keys.Add((entry.EncryptionType, entry.Key));
            }
            else if (!keys[existing].Value.AsSpan().SequenceEqual(entry.Key))
            {
                error = new ErrorRecord(
                    new ArgumentException(
                        $"The keytab entries have different {entry.EncryptionType} keys with kvno {selectedKvno} " +
                        $"for {fullName}, including the entry for {entry.FullName}"),
                    "KeytabKeyConflict",
                    ErrorCategory.InvalidData,
                    fullName);
                return null;
            }
        }

        // Without a kvno a type missing from the newest keys is most likely an old key that was not updated.
        if (kvno is null)
        {
            foreach (IGrouping<EncryptionType, ObolKeytabEntry> older in usable
                .Where(e => e.Kvno < selectedKvno && !keys.Any(k => k.Type == e.EncryptionType))
                .GroupBy(e => e.EncryptionType))
            {
                cmdlet.WriteWarning(
                    $"Ignoring the {older.Key} key of {fullName} with kvno {older.Max(e => e.Kvno)}, the newest " +
                    $"keys with kvno {selectedKvno} have no {older.Key} key");
            }
        }

        return new ImportedKeys(selectedKvno, [.. keys]);
    }
}
