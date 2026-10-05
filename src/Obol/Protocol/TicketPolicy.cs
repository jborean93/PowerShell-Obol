using System;
using System.Collections.Generic;
using Kerberos.NET.Entities;
using Obol.Kerberos;

namespace Obol.Protocol;

/// <summary>The rules shared by the AS and TGS exchanges for the tickets they issue.</summary>
internal static class TicketPolicy
{
    /// <summary>The allowed difference between the client and KDC clocks, the MIT and AD default.</summary>
    public static readonly TimeSpan MaximumSkew = TimeSpan.FromMinutes(5);

    /// <summary>The longest ticket lifetime, the AD default.</summary>
    public static readonly TimeSpan MaximumLifetime = TimeSpan.FromHours(10);

    /// <summary>The longest time a ticket can be renewed for, the AD default.</summary>
    public static readonly TimeSpan MaximumRenewableLifetime = TimeSpan.FromDays(7);

    /// <summary>
    /// Selects the session key type, the first type the client requested the service has a key for. Like AD this
    /// limits the session key to the types the service supports.
    /// </summary>
    public static EncryptionType? SelectSessionKeyType(
        IEnumerable<EncryptionType> requested,
        KdcPrincipal service)
    {
        foreach (EncryptionType etype in requested)
        {
            if (service.GetKey(etype) is not null)
            {
                return etype;
            }
        }
        return null;
    }

    /// <summary>Computes the ticket times and sets the renewable flag following RFC 4120 3.1.3.</summary>
    /// <param name="body">The request body with the requested times and options.</param>
    /// <param name="now">The current time, also the start time as postdating is not supported.</param>
    /// <param name="flags">The flags of the new ticket, the renewable flag is added if it is granted.</param>
    /// <param name="maxEndTime">The latest end time allowed, the end time of the TGT for a TGS request.</param>
    /// <param name="maxRenewTill">The latest renew-till allowed, the renew-till of the TGT for a TGS request.</param>
    public static TicketTimes Compute(
        KrbKdcReqBody body,
        DateTimeOffset now,
        ref TicketFlag flags,
        DateTimeOffset? maxEndTime,
        DateTimeOffset? maxRenewTill)
    {
        DateTimeOffset start = now;

        // A till in the past, such as the 19700101000000Z the RFC uses for no limit, means the maximum.
        DateTimeOffset till = body.Till > start ? body.Till : DateTimeOffset.MaxValue;
        DateTimeOffset end = Min(till, start + MaximumLifetime, maxEndTime);

        KdcOption options = body.KdcOptions.ToObol();
        bool renewableOk = options.HasFlag(KdcOption.RenewableOk) && till > end;
        if (options.HasFlag(KdcOption.Renewable) || renewableOk)
        {
            // RENEWABLE-OK asks for a renewable ticket up to the requested till instead.
            DateTimeOffset requested = options.HasFlag(KdcOption.Renewable) && body.RTime > start
                ? body.RTime.Value
                : renewableOk ? till : DateTimeOffset.MaxValue;
            DateTimeOffset renewTill = Min(requested, start + MaximumRenewableLifetime, maxRenewTill);

            // A renew-till not after the end time gives nothing to renew.
            if (renewTill > end)
            {
                flags |= TicketFlag.Renewable;
                return new TicketTimes(start, end, renewTill);
            }
        }

        return new TicketTimes(start, end, null);
    }

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b, DateTimeOffset? c)
    {
        DateTimeOffset min = a < b ? a : b;
        return c is DateTimeOffset value && value < min ? value : min;
    }
}
