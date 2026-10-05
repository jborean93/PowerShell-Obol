using System;
using System.Collections.Generic;
using System.Net;

namespace Obol;

/// <summary>An LDAP ping to the DC locator CLDAP responder and the reply sent.</summary>
internal sealed class DcLocatorLdapExchange : DcLocatorExchange
{
    /// <summary>The LDAP message ID, null if the request was not decoded that far.</summary>
    public int? MessageId { get; set; }

    /// <summary>Whether the request is a search request, the form of an LDAP ping.</summary>
    public bool IsSearch { get; set; }

    /// <summary>The equality matches of the search filter, the values of the ping.</summary>
    public Dictionary<string, byte[]> Filter { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The host name of the KDC in the NETLOGON_SAM_LOGON_RESPONSE_EX sent, null if none was sent.</summary>
    public string? DcHostName { get; set; }

    /// <summary>The address of the KDC in <see cref="DcHostName"/>.</summary>
    public IPAddress? DcAddress { get; set; }

    /// <summary>The DS_FLAG values in the NETLOGON_SAM_LOGON_RESPONSE_EX sent.</summary>
    public uint DcFlags { get; set; }
}
