namespace Obol.Protocol;

/// <summary>Why a change to the principal store was rejected.</summary>
internal enum PrincipalStoreError
{
    /// <summary>The name or an alias is already used by a principal.</summary>
    AlreadyExists,

    /// <summary>The principal has been removed.</summary>
    NotFound,

    /// <summary>The encryption types cannot be used, such as adding one without new keys.</summary>
    InvalidEncryptionType,

    /// <summary>The change is not allowed for the KDC's krbtgt principal.</summary>
    Krbtgt,

    /// <summary>The RID is already used by a principal.</summary>
    RidAlreadyUsed,
}
