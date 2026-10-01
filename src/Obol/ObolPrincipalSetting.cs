using System.Security;

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
    public ObolPrincipalFlag Flag { get; set; }

    /// <summary>The encryption types to create keys for in order of preference, AES256 and AES128 if not set.</summary>
    public ObolEncryptionType[]? EncryptionType { get; set; }

    /// <summary>Other names the KDC finds the principal by.</summary>
    public string[]? Alias { get; set; }

    /// <summary>The RID of the principal, the next unused RID from 1000 if not set.</summary>
    public int? Rid { get; set; }
}
