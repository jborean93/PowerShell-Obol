using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities.Pac;
using Obol.Kerberos;
using EncryptionType = Obol.Kerberos.EncryptionType;
using KrbEncryptionType = Kerberos.NET.Crypto.EncryptionType;

namespace Obol.Protocol;

/// <summary>The principals of the realm served by an <see cref="ObolKdc"/>.</summary>
internal sealed class PrincipalStore
{
    /// <summary>The encryption types keys can be created for, in the default order of preference.</summary>
    internal static readonly EncryptionType[] SupportedEncryptionTypes =
    [
        EncryptionType.Aes256Sha1,
        EncryptionType.Aes128Sha1,
        EncryptionType.Aes256Sha384,
        EncryptionType.Aes128Sha256,
    ];

    /// <summary>The encryption types a new principal gets keys for, the AD and MIT defaults.</summary>
    internal static readonly EncryptionType[] DefaultEncryptionTypes =
    [
        EncryptionType.Aes256Sha1,
        EncryptionType.Aes128Sha1,
    ];

    /// <summary>
    /// The account control bits a principal can have set, the ones the KDC acts on. They are the MS-SAMR USER_* values
    /// the PAC carries, the AD userAccountControl numbers differ.
    /// </summary>
    internal const PacUserAccountControl SupportedAccountControl = PacUserAccountControl.DontRequirePreAuth
        | PacUserAccountControl.NotDelegated
        | PacUserAccountControl.TrustedForDelegation
        | PacUserAccountControl.NoAuthDataRequired;

    /// <summary>The well known RID of the krbtgt account in AD.</summary>
    private const uint KrbtgtRid = 502;

    /// <summary>The well known RID of the Domain Users group in AD, used as every principal's primary group.</summary>
    internal const uint DomainUsersRid = 513;

    /// <summary>The first RID given to a principal, AD starts new accounts at 1000 or above.</summary>
    private const uint FirstRid = 1000;

    /// <summary>The principals by name and alias.</summary>
    private readonly Dictionary<string, ObolPrincipal> _names;
    private readonly List<ObolPrincipal> _ordered = [];

    /// <summary>The principals by RID.</summary>
    private readonly Dictionary<uint, ObolPrincipal> _rids = [];
    private uint _nextRid = FirstRid;

    /// <param name="realm">The realm of the principals.</param>
    /// <param name="caseInsensitive">Whether principal names are matched case insensitively.</param>
    /// <param name="domainSid">
    /// The three values after S-1-5-21- of the domain SID, see <see cref="TryParseDomainSid"/>, random if not set.
    /// </param>
    public PrincipalStore(string realm, bool caseInsensitive, uint[]? domainSid = null)
    {
        Realm = realm;
        CaseInsensitive = caseInsensitive;
        _names = new(caseInsensitive ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

        // A random domain SID like AD's S-1-5-21-x-y-z so principals in different KDCs have different SIDs.
        domainSid ??= [.. Enumerable.Range(0, 3)
            .Select(_ => BinaryPrimitives.ReadUInt32LittleEndian(RandomNumberGenerator.GetBytes(4)))];
        DomainSid = new SecurityIdentifier(IdentifierAuthority.NTAuthority, [21, .. domainSid], 0);

        // The krbtgt has a key for every type so any client can use the session key it prefers.
        Krbtgt = Add(
            ["krbtgt", realm],
            new PrincipalState(CreateRandomKeys(SupportedEncryptionTypes, 1), 1, PacUserAccountControl.None, []),
            KrbtgtRid);
    }

    /// <summary>The realm the principals belong to.</summary>
    public string Realm { get; }

    /// <summary>Whether principal names are matched case insensitively.</summary>
    public bool CaseInsensitive { get; }

    /// <summary>The SID of the domain the PAC is generated for.</summary>
    public SecurityIdentifier DomainSid { get; }

    /// <summary>Parses a domain SID in the AD form S-1-5-21-a-b-c.</summary>
    /// <param name="value">The SID string.</param>
    /// <param name="subAuthorities">The three values after S-1-5-21-.</param>
    /// <returns>Whether the value is a valid domain SID.</returns>
    public static bool TryParseDomainSid(string value, [NotNullWhen(true)] out uint[]? subAuthorities)
    {
        subAuthorities = null;
        const string prefix = "S-1-5-21-";
        if (!value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string[] parts = value[prefix.Length..].Split('-');
        if (parts.Length != 3)
        {
            return false;
        }

        uint[] values = new uint[parts.Length];
        for (int i = 0; i < parts.Length; i++)
        {
            if (!uint.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out values[i]))
            {
                return false;
            }
        }

        subAuthorities = values;
        return true;
    }

    /// <summary>The KDC's krbtgt principal.</summary>
    public ObolPrincipal Krbtgt { get; }

    /// <summary>The principals in the order they were added.</summary>
    public ObolPrincipal[] Principals
    {
        get
        {
            lock (_names)
            {
                return [.. _ordered];
            }
        }
    }

    /// <summary>
    /// Creates a principal with keys derived from a password, existing keys, or random keys if neither is set.
    /// </summary>
    /// <param name="components">The name components of the principal.</param>
    /// <param name="password">The password to derive the keys from, or null to create random keys.</param>
    /// <param name="flags">The options of the principal.</param>
    /// <param name="encryptionTypes">The encryption types to create keys for, null for the defaults.</param>
    /// <param name="aliases">The name components of other names the principal can be found by.</param>
    /// <param name="rid">The RID of the principal, the next unused RID from 1000 if not set.</param>
    /// <param name="salt">The salt of the password or existing keys, the default salt of the name if not set.</param>
    /// <param name="importedKeys">Existing keys to use instead of a password.</param>
    /// <param name="kvno">The key version number, the kvno of the imported keys or 1 if not set.</param>
    public ObolPrincipal Create(
        string[] components,
        SecureString? password,
        PacUserAccountControl flags,
        EncryptionType[]? encryptionTypes = null,
        string[][]? aliases = null,
        uint? rid = null,
        string? salt = null,
        ImportedKeys? importedKeys = null,
        int? kvno = null)
    {
        EncryptionType[] etypes = encryptionTypes ?? DefaultEncryptionTypes;
        string keySalt = salt ?? GetSalt(components);
        int keyKvno = kvno ?? importedKeys?.Kvno ?? 1;
        KerberosKey[] keys;
        if (importedKeys is not null)
        {
            keys = CreateImportedKeys(importedKeys, keySalt, keyKvno);
        }
        else if (password is not null)
        {
            keys = CreatePasswordKeys(password, keySalt, etypes, keyKvno);
        }
        else
        {
            keys = CreateRandomKeys(etypes, keyKvno);
        }
        string[] aliasNames = aliases?.Select(PrincipalName.Unparse).ToArray() ?? [];

        lock (_names)
        {
            string name = PrincipalName.Unparse(components);
            CheckNamesAvailable(null, [name, .. aliasNames]);

            uint principalRid;
            if (rid is uint requested)
            {
                if (_rids.TryGetValue(requested, out ObolPrincipal? existing))
                {
                    throw new PrincipalStoreException(PrincipalStoreError.RidAlreadyUsed,
                        $"The RID {requested} is already used by the principal '{existing.FullName}'");
                }
                principalRid = requested;
            }
            else
            {
                // RIDs are not reused after a principal is removed, like AD, and skip any RID that was set.
                while (_rids.ContainsKey(_nextRid))
                {
                    _nextRid++;
                }
                principalRid = _nextRid++;
            }

            return Add(components, new PrincipalState(keys, keyKvno, flags, aliasNames), principalRid);
        }
    }

    /// <summary>Changes a principal, a null argument leaves that value as it is.</summary>
    /// <param name="principal">The principal to change.</param>
    /// <param name="password">The password to derive new keys from.</param>
    /// <param name="newRandomKey">Whether to create new random keys.</param>
    /// <param name="encryptionTypes">
    /// The encryption types to keep keys for. Without new keys only existing types can be kept, they cannot be
    /// derived again as the password is not stored.
    /// </param>
    /// <param name="flags">The options to replace the existing options with.</param>
    /// <param name="aliases">The aliases to replace the existing aliases with.</param>
    /// <param name="salt">The salt of the password or existing keys, the default salt of the name if not set.</param>
    /// <param name="importedKeys">Existing keys to replace the keys with, they keep their kvno.</param>
    /// <param name="kvno">
    /// The key version number. New keys get the current kvno plus one, or the kvno of imported keys, if not set.
    /// Without new keys the existing keys are given this kvno, like MIT kadmin modprinc -kvno.
    /// </param>
    public void Update(
        ObolPrincipal principal,
        SecureString? password = null,
        bool newRandomKey = false,
        EncryptionType[]? encryptionTypes = null,
        PacUserAccountControl? flags = null,
        string[][]? aliases = null,
        string? salt = null,
        ImportedKeys? importedKeys = null,
        int? kvno = null)
    {
        // Derive the keys outside the lock, the iterations take a while. The kvno is set under the lock as another
        // update may finish while the keys are derived.
        PrincipalState current = principal.State;
        EncryptionType[] etypes = encryptionTypes ?? current.EncryptionTypes;
        string keySalt = salt ?? GetSalt(principal.Components);
        KerberosKey[]? newKeys = null;
        if (importedKeys is not null)
        {
            newKeys = CreateImportedKeys(importedKeys, keySalt, importedKeys.Kvno);
        }
        else if (password is not null || newRandomKey)
        {
            newKeys = password is null
                ? CreateRandomKeys(etypes, 0)
                : CreatePasswordKeys(password, keySalt, etypes, 0);
        }

        lock (_names)
        {
            if (!_names.TryGetValue(principal.Name, out ObolPrincipal? existing) || existing != principal)
            {
                throw new PrincipalStoreException(PrincipalStoreError.NotFound,
                    $"The principal '{principal.FullName}' does not exist");
            }

            // Base the change on the latest values in case another update happened while the keys were derived.
            current = principal.State;
            // Imported keys keep the kvno they were issued with so tickets match the service's keytab.
            int newKvno = newKeys is null
                ? kvno ?? current.Kvno
                : kvno ?? importedKeys?.Kvno ?? current.Kvno + 1;
            KerberosKey[] keys = newKeys ?? SelectExistingKeys(principal, current, etypes);
            if (newKeys is not null || newKvno != current.Kvno)
            {
                keys = [.. keys.Select(k => new KerberosKey(
                    key: k.GetKey().ToArray(),
                    salt: k.Salt,
                    etype: k.EncryptionType,
                    kvno: newKvno))];
            }

            string[] aliasNames = current.Aliases;
            if (aliases is not null)
            {
                if (principal.IsKrbtgt && aliases.Length > 0)
                {
                    throw new PrincipalStoreException(PrincipalStoreError.Krbtgt,
                        "The krbtgt principal cannot have aliases");
                }

                aliasNames = [.. aliases.Select(PrincipalName.Unparse)];
                CheckNamesAvailable(principal, aliasNames);

                foreach (string alias in current.Aliases)
                {
                    _names.Remove(alias);
                }
                foreach (string alias in aliasNames)
                {
                    _names[alias] = principal;
                }
            }

            principal.State = new PrincipalState(
                keys,
                newKvno,
                flags ?? current.Flags,
                aliasNames);
        }
    }

    /// <summary>Removes a principal so it can no longer be used.</summary>
    public void Remove(ObolPrincipal principal)
    {
        if (principal.IsKrbtgt)
        {
            throw new PrincipalStoreException(PrincipalStoreError.Krbtgt,
                "The krbtgt principal cannot be removed");
        }

        lock (_names)
        {
            if (!_names.TryGetValue(principal.Name, out ObolPrincipal? existing) || existing != principal)
            {
                throw new PrincipalStoreException(PrincipalStoreError.NotFound,
                    $"The principal '{principal.FullName}' does not exist");
            }

            _names.Remove(principal.Name);
            foreach (string alias in principal.State.Aliases)
            {
                _names.Remove(alias);
            }
            _ordered.Remove(principal);
            _rids.Remove(principal.Rid);
        }
    }

    /// <summary>Finds a principal by its name or an alias.</summary>
    public ObolPrincipal? Find(string[] components)
    {
        // Names are stored in their escaped form so each set of components has a single key.
        if (components.Length == 0)
        {
            return null;
        }

        lock (_names)
        {
            return _names.GetValueOrDefault(PrincipalName.Unparse(components));
        }
    }

    private ObolPrincipal Add(string[] components, PrincipalState state, uint rid)
    {
        ObolPrincipal principal = new(this, components, state, rid, new SecurityIdentifier(DomainSid, rid).ToString());

        lock (_names)
        {
            _names.Add(principal.Name, principal);
            foreach (string alias in state.Aliases)
            {
                _names.Add(alias, principal);
            }
            _ordered.Add(principal);
            _rids.Add(rid, principal);
        }

        return principal;
    }

    /// <summary>Checks the names are not used by another principal or repeated.</summary>
    private void CheckNamesAvailable(ObolPrincipal? owner, string[] names)
    {
        HashSet<string> seen = new(_names.Comparer);
        if (owner is not null)
        {
            seen.Add(owner.Name);
        }

        foreach (string name in names)
        {
            if (!seen.Add(name) ||
                (_names.TryGetValue(name, out ObolPrincipal? existing) && existing != owner))
            {
                throw new PrincipalStoreException(PrincipalStoreError.AlreadyExists,
                    $"The principal name '{name}@{Realm}' is already used");
            }
        }
    }

    private static KerberosKey[] SelectExistingKeys(
        ObolPrincipal principal,
        PrincipalState state,
        EncryptionType[] etypes)
    {
        KerberosKey[] keys = new KerberosKey[etypes.Length];
        for (int i = 0; i < etypes.Length; i++)
        {
            keys[i] = state.GetKey(etypes[i]) ?? throw new PrincipalStoreException(
                PrincipalStoreError.InvalidEncryptionType,
                $"The principal '{principal.FullName}' has no {etypes[i]} key, set a password " +
                "or new random key to create keys for new encryption types");
        }
        return keys;
    }

    private static KerberosKey[] CreateImportedKeys(ImportedKeys importedKeys, string salt, int kvno)
    {
        return [.. importedKeys.Keys.Select(k => new KerberosKey(
            key: k.Value.ToArray(),
            salt: salt,
            etype: k.Type.ToKerberosNet(),
            kvno: kvno))];
    }

    /// <summary>Derives the key of each encryption type from a password, RFC 3962 and RFC 8009 string-to-key.</summary>
    /// <param name="password">The password to derive the keys from.</param>
    /// <param name="salt">The salt to derive the keys with.</param>
    /// <param name="etypes">The encryption types to derive a key for.</param>
    /// <returns>The key values in the order of the encryption types.</returns>
    public static byte[][] DeriveKeys(SecureString password, string salt, EncryptionType[] etypes)
    {
        return [.. CreatePasswordKeys(password, salt, etypes, 0).Select(k => k.GetKey().ToArray())];
    }

    /// <summary>The default salt from RFC 4120 4. of a principal in a realm.</summary>
    public static string GetDefaultSalt(string realm, string[] components) => realm + string.Concat(components);

    /// <summary>The default salt from RFC 4120 4., the realm followed by each name component.</summary>
    private string GetSalt(string[] components) => GetDefaultSalt(Realm, components);

    private static KerberosKey[] CreateRandomKeys(EncryptionType[] etypes, int kvno)
    {
        // The AES random-to-key function is the identity, RFC 3962 6. and RFC 8009 3.
        return [.. etypes.Select(etype => new KerberosKey(
            key: RandomNumberGenerator.GetBytes(GetKeySize(etype)),
            etype: etype.ToKerberosNet(),
            kvno: kvno))];
    }

    private static KerberosKey[] CreatePasswordKeys(
        SecureString password,
        string salt,
        EncryptionType[] etypes,
        int kvno)
    {
        // Kerberos.NET takes the password as UTF-16 bytes, copy them out of the SecureString without creating a
        // string that cannot be cleared.
        byte[] passwordBytes = new byte[password.Length * 2];
        IntPtr ptr = Marshal.SecureStringToGlobalAllocUnicode(password);
        try
        {
            Marshal.Copy(ptr, passwordBytes, 0, passwordBytes.Length);

            return [.. etypes.Select(etype =>
            {
                KrbEncryptionType krbEType = etype.ToKerberosNet();
                KerberosKey passwordKey = new(password: passwordBytes, salt: salt, etype: krbEType);
                return new KerberosKey(
                    key: passwordKey.GetKey().ToArray(),
                    salt: salt,
                    etype: krbEType,
                    kvno: kvno);
            })];
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    /// <summary>The size in bytes of a key of the encryption type.</summary>
    public static int GetKeySize(EncryptionType etype) => etype switch
    {
        EncryptionType.Aes128Sha1 or EncryptionType.Aes128Sha256 => 16,
        EncryptionType.Aes256Sha1 or EncryptionType.Aes256Sha384 => 32,
        _ => throw new ArgumentOutOfRangeException(nameof(etype)),
    };
}
