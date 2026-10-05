using System.Security;
using Obol.Kerberos;

namespace Obol;

/// <summary>The settings to create a principal with, used by New-ObolPrincipal and Start-ObolKdc -Principal.</summary>
/// <remarks>
/// Created with New-ObolPrincipalSetting or by casting a hashtable of the properties, the properties not set use the
/// same defaults as New-ObolPrincipal.
/// </remarks>
public sealed class ObolPrincipalSetting
{
    /// <summary>The password to derive the keys from, random keys are created if not set.</summary>
    public SecureString? Password { get; set; }

    /// <summary>The options to turn on for the principal.</summary>
    public PacUserAccountControl Flag { get; set; }

    /// <summary>The encryption types to create keys for in order of preference, AES256 and AES128 if not set.</summary>
    public EncryptionType[]? EncryptionType { get; set; }

    /// <summary>Other names the KDC finds the principal by.</summary>
    public string[]? Alias { get; set; }

    /// <summary>
    /// Keytab entries to take the keys from instead of a password, see Import-ObolKeytab. Only the entries for the
    /// principal name or an alias are used.
    /// </summary>
    public ObolKeytabEntry[]? Key { get; set; }

    /// <summary>
    /// The key version number of the principal, 1 if not set. With <see cref="Key"/> the keys are taken from the
    /// entries with this kvno, the newest kvno of the entries if not set.
    /// </summary>
    public int? Kvno { get; set; }

    /// <summary>The salt of the password or keys, the default salt of the realm and name if not set.</summary>
    public string? Salt { get; set; }

    /// <summary>The RID of the principal, the next unused RID from 1000 if not set.</summary>
    public int? Rid { get; set; }
}
