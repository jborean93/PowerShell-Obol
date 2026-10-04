using System;

namespace Obol;

/// <summary>Options that can be turned on for a principal.</summary>
/// <remarks>
/// The names follow the AD userAccountControl flags where one exists but the values are Obol's own, see the
/// New-ObolPrincipal -Flag help for the AD and MIT equivalents.
/// </remarks>
[Flags]
public enum ObolPrincipalFlag
{
    /// <summary>No options are set.</summary>
    None = 0,

    /// <summary>The principal can get a ticket without pre-authentication.</summary>
    DoesNotRequirePreAuth = 1 << 0,

    /// <summary>The principal never gets a forwardable ticket so its credentials cannot be delegated.</summary>
    NotDelegated = 1 << 1,

    /// <summary>Tickets for the principal have the OK-AS-DELEGATE flag, clients can delegate to it.</summary>
    TrustedForDelegation = 1 << 2,

    /// <summary>Tickets for the principal as a service have no PAC, TGTs always have one.</summary>
    NoAuthDataRequired = 1 << 3,
}
