using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Security;
using Obol.Protocol;

namespace Obol.Commands;

/// <summary>Validation shared by the cmdlets that create or change principals.</summary>
internal static class PrincipalCommandHelper
{
    /// <summary>Parses a principal name for the KDC, the realm suffix must match the KDC realm.</summary>
    /// <param name="name">The name to parse.</param>
    /// <param name="realm">The realm of the KDC.</param>
    /// <param name="error">The error to write if the name is invalid.</param>
    /// <returns>The name components or null if the name is invalid.</returns>
    public static string[]? ParseName(string name, string realm, out ErrorRecord? error)
    {
        error = null;
        if (!PrincipalName.TryParse(name, out string[]? components, out string? nameRealm, out string? parseError))
        {
            error = new ErrorRecord(
                new ArgumentException($"Invalid principal name '{name}': {parseError}"),
                "InvalidPrincipalName",
                ErrorCategory.InvalidArgument,
                name);
            return null;
        }

        if (nameRealm is not null && !string.Equals(nameRealm, realm, StringComparison.Ordinal))
        {
            error = new ErrorRecord(
                new ArgumentException($"The principal realm '{nameRealm}' does not match the KDC realm '{realm}'"),
                "PrincipalRealmMismatch",
                ErrorCategory.InvalidArgument,
                name);
            return null;
        }

        return components;
    }

    /// <summary>Parses a principal name not tied to a KDC, the realm comes from the name or the argument.</summary>
    /// <param name="name">The name to parse, such as <c>user@EXAMPLE.TEST</c> or <c>user</c>.</param>
    /// <param name="realm">The realm for a name without one, must match the name's realm if both are set.</param>
    /// <param name="nameRealm">The realm of the principal.</param>
    /// <param name="error">The error to write if the name is invalid or has no realm.</param>
    /// <returns>The name components or null if the name is invalid.</returns>
    public static string[]? ParseNameWithRealm(
        string name,
        string? realm,
        out string nameRealm,
        out ErrorRecord? error)
    {
        nameRealm = "";
        error = null;
        if (!PrincipalName.TryParse(name, out string[]? components, out string? parsedRealm, out string? parseError))
        {
            error = new ErrorRecord(
                new ArgumentException($"Invalid principal name '{name}': {parseError}"),
                "InvalidPrincipalName",
                ErrorCategory.InvalidArgument,
                name);
            return null;
        }

        if (parsedRealm is not null && realm is not null &&
            !string.Equals(parsedRealm, realm, StringComparison.Ordinal))
        {
            error = new ErrorRecord(
                new ArgumentException($"The principal realm '{parsedRealm}' does not match the realm '{realm}'"),
                "PrincipalRealmMismatch",
                ErrorCategory.InvalidArgument,
                name);
            return null;
        }

        if ((parsedRealm ?? realm) is not string resolved)
        {
            error = new ErrorRecord(
                new ArgumentException($"The principal name '{name}' has no realm, add it after '@' or set -Realm"),
                "RealmRequired",
                ErrorCategory.InvalidArgument,
                name);
            return null;
        }

        nameRealm = resolved;
        return components;
    }

    /// <summary>Parses each alias, see <see cref="ParseName"/>.</summary>
    public static string[][]? ParseAliases(string[]? aliases, string realm, out ErrorRecord? error)
    {
        error = null;
        if (aliases is null)
        {
            return null;
        }

        string[][] parsed = new string[aliases.Length][];
        for (int i = 0; i < aliases.Length; i++)
        {
            // An alias set through a hashtable is not checked by the parameter validation.
            if (string.IsNullOrEmpty(aliases[i]))
            {
                error = new ErrorRecord(
                    new ArgumentException("An alias must not be null or empty"),
                    "InvalidPrincipalName",
                    ErrorCategory.InvalidArgument,
                    aliases[i]);
                return null;
            }

            string[]? components = ParseName(aliases[i], realm, out error);
            if (components is null)
            {
                return null;
            }
            parsed[i] = components;
        }
        return parsed;
    }

    /// <summary>Checks the flags only contain defined values.</summary>
    /// <returns>The error to write, or null if the flags are valid.</returns>
    public static ErrorRecord? CheckFlags(ObolPrincipalFlag flags)
    {
        // PowerShell binding rejects undefined values but [Enum]::ToObject can still create one.
        ObolPrincipalFlag known = Enum.GetValues<ObolPrincipalFlag>().Aggregate((a, b) => a | b);
        if ((flags & ~known) == 0)
        {
            return null;
        }

        return new ErrorRecord(
            new ArgumentException(
                $"Flag value {(int)flags} contains values that are not supported, valid values are " +
                string.Join(", ", Enum.GetNames<ObolPrincipalFlag>())),
            "InvalidFlag",
            ErrorCategory.InvalidArgument,
            flags);
    }

    /// <summary>Checks the encryption types are not empty, unique and defined.</summary>
    /// <returns>The encryption types, or null if not set or invalid.</returns>
    public static ObolEncryptionType[]? CheckEncryptionTypes(ObolEncryptionType[]? types, out ErrorRecord? error)
    {
        error = null;
        if (types is null)
        {
            return null;
        }

        if (types.Length == 0 || types.Distinct().Count() != types.Length)
        {
            error = new ErrorRecord(
                new ArgumentException("EncryptionType must contain at least one value and no duplicates"),
                "InvalidEncryptionType",
                ErrorCategory.InvalidArgument,
                types);
            return null;
        }

        // PowerShell binding rejects undefined values but [Enum]::ToObject can still create one.
        foreach (ObolEncryptionType type in types)
        {
            if (!Enum.IsDefined(type))
            {
                error = new ErrorRecord(
                    new ArgumentException(
                        $"EncryptionType '{type}' is not supported, valid values are " +
                        string.Join(", ", Enum.GetNames<ObolEncryptionType>())),
                    "InvalidEncryptionType",
                    ErrorCategory.InvalidArgument,
                    types);
                return null;
            }
        }

        return types;
    }

    /// <summary>Checks the parameters that decide the keys of a principal can be used together.</summary>
    /// <returns>The error to write, or null if the parameters are valid.</returns>
    public static ErrorRecord? CheckKeyParameters(
        SecureString? password,
        bool newRandomKey,
        ObolEncryptionType[]? encryptionTypes,
        ObolKeytabEntry[]? key,
        int? kvno,
        string? salt)
    {
        (string? errorId, string? message) = (password, newRandomKey, encryptionTypes, key, kvno, salt) switch
        {
            (not null, true, _, _, _, _) => ("PasswordWithNewRandomKey",
                "Password and NewRandomKey cannot be set together"),
            ({ Length: 0 }, _, _, _, _, _) => ("EmptyPassword", "The password must not be empty"),
            (not null, _, _, not null, _, _) => ("KeyWithPassword", "Key and Password cannot be set together"),
            (_, true, _, not null, _, _) => ("KeyWithNewRandomKey", "Key and NewRandomKey cannot be set together"),
            (_, _, not null, not null, _, _) => ("KeyWithEncryptionType",
                "Key and EncryptionType cannot be set together, the keys decide the encryption types, filter the " +
                "keytab entries to choose them"),
            (_, _, _, _, < 0, _) => ("InvalidKvno", $"Kvno must be 0 or greater, got {kvno}"),
            (null, _, _, null, _, not null) => ("SaltWithoutKey",
                "Salt can only be set with Password or Key, random keys have no password to derive"),
            _ => (null, null),
        };

        return errorId is null
            ? null
            : new ErrorRecord(new ArgumentException(message), errorId, ErrorCategory.InvalidArgument, null);
    }

    /// <summary>Finds the principals of a KDC by name or alias for the -Kdc and -Name parameters.</summary>
    /// <param name="cmdlet">The cmdlet to write an error for each name that is invalid or not found.</param>
    /// <param name="kdc">The KDC to find the principals in.</param>
    /// <param name="names">The names or aliases, matched like the KDC matches names in requests.</param>
    public static List<ObolPrincipal> FindByName(Cmdlet cmdlet, ObolKdc kdc, string[] names)
    {
        List<ObolPrincipal> principals = [];
        foreach (string name in names)
        {
            string[]? components = ParseName(name, kdc.Realm, out ErrorRecord? error);
            if (components is null)
            {
                cmdlet.WriteError(error!);
                continue;
            }

            ObolPrincipal? principal = kdc.Store.Find(components);
            if (principal is null)
            {
                string fullName = $"{PrincipalName.Unparse(components)}@{kdc.Realm}";
                cmdlet.WriteError(new ErrorRecord(
                    new ItemNotFoundException($"The principal '{fullName}' does not exist"),
                    "PrincipalNotFound",
                    ErrorCategory.ObjectNotFound,
                    name));
                continue;
            }

            principals.Add(principal);
        }
        return principals;
    }

    /// <summary>The error record for a change the principal store rejected.</summary>
    public static ErrorRecord StoreError(PrincipalStoreException exception, object target)
    {
        (string errorId, ErrorCategory category) = exception.Error switch
        {
            PrincipalStoreError.AlreadyExists => ("PrincipalAlreadyExists", ErrorCategory.ResourceExists),
            PrincipalStoreError.NotFound => ("PrincipalNotFound", ErrorCategory.ObjectNotFound),
            PrincipalStoreError.InvalidEncryptionType => ("InvalidEncryptionType", ErrorCategory.InvalidArgument),
            PrincipalStoreError.RidAlreadyUsed => ("PrincipalRidAlreadyUsed", ErrorCategory.ResourceExists),
            _ => ("KrbtgtPrincipal", ErrorCategory.InvalidOperation),
        };
        return new ErrorRecord(exception, errorId, category, target);
    }
}
