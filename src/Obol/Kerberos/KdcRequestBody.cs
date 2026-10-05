using System;

namespace Obol.Kerberos;

/// <summary>The KDC-REQ-BODY of an AS-REQ or TGS-REQ, RFC 4120 5.4.1, what the client asked for.</summary>
public sealed class KdcRequestBody
{
    internal KdcRequestBody() { }

    /// <summary>The kdc-options, the ticket flags and behaviour the client asked for.</summary>
    public KdcOption KdcOption { get; internal init; }

    /// <summary>
    /// The cname, the client in an AS-REQ. Usually absent in a TGS-REQ, where the TGT names the client.
    /// </summary>
    public PrincipalName? ClientName { get; internal init; }

    /// <summary>The realm of the request, the realm of the service and of the client name.</summary>
    public string Realm { get; internal init; } = "";

    /// <summary>The sname, the service the ticket is for.</summary>
    public PrincipalName? ServiceName { get; internal init; }

    /// <summary>The from time of a postdated ticket, if asked for.</summary>
    public DateTime? From { get; internal init; }

    /// <summary>The till time, when the client wants the ticket to expire.</summary>
    public DateTime Till { get; internal init; }

    /// <summary>The rtime, how long the client wants to be able to renew the ticket for, if asked for.</summary>
    public DateTime? RenewTill { get; internal init; }

    /// <summary>The nonce the reply must echo.</summary>
    public int Nonce { get; internal init; }

    /// <summary>The encryption types the client accepts, as their IANA numbers in order of preference.</summary>
    public EncryptionType[] EncryptionType { get; internal init; } = [];

    /// <summary>The addresses the ticket should be valid from, usually none.</summary>
    public HostAddress[] Address { get; internal init; } = [];

    /// <summary>
    /// The enc-authorization-data the client wants in the ticket, encrypted with the subkey or session key of a
    /// TGS-REQ, if sent.
    /// </summary>
    public EncryptedData? EncryptedAuthorizationData { get; internal init; }

    /// <summary>
    /// The additional-tickets, the TGT of the service for user to user authentication or the evidence ticket of
    /// S4U2proxy.
    /// </summary>
    public Ticket[] AdditionalTicket { get; internal init; } = [];

    public override string ToString() => ClientName is null ? $"-> {ServiceName}" : $"{ClientName} -> {ServiceName}";
}
