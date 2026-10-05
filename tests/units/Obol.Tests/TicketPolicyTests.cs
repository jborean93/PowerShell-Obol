using System;
using System.Threading.Tasks;
using Kerberos.NET.Entities;
using Obol.Protocol;

namespace Obol.Tests;

/// <summary>The ticket time and renewable rules, the realm allows 10 hours and renewals for 7 days.</summary>
public class TicketPolicyTests
{
    private static readonly DateTimeOffset s_now = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);

    private static (TicketTimes Times, Kerberos.TicketFlag Flags) Compute(
        KdcOptions options,
        DateTimeOffset till,
        DateTimeOffset? rtime = null,
        DateTimeOffset? maxEndTime = null,
        DateTimeOffset? maxRenewTill = null)
    {
        KrbKdcReqBody body = new()
        {
            KdcOptions = options,
            Till = till,
            RTime = rtime,
        };
        Kerberos.TicketFlag flags = Kerberos.TicketFlag.None;
        TicketTimes times = TicketPolicy.Compute(body, s_now, ref flags, maxEndTime, maxRenewTill);
        return (times, flags);
    }

    [Test]
    public async Task EndsAtMaximumLifetime()
    {
        (TicketTimes times, Kerberos.TicketFlag flags) = Compute(0, s_now.AddDays(1));

        await Assert.That(times.Start).IsEqualTo(s_now);
        await Assert.That(times.End).IsEqualTo(s_now.AddHours(10));
        await Assert.That(times.RenewTill).IsNull();
        await Assert.That(flags).IsEqualTo(Kerberos.TicketFlag.None);
    }

    [Test]
    public async Task EndsAtRequestedTill()
    {
        (TicketTimes times, _) = Compute(0, s_now.AddHours(1));

        await Assert.That(times.End).IsEqualTo(s_now.AddHours(1));
    }

    [Test]
    public async Task TillInThePastMeansNoLimit()
    {
        (TicketTimes times, _) = Compute(0, DateTimeOffset.UnixEpoch);

        await Assert.That(times.End).IsEqualTo(s_now.AddHours(10));
    }

    [Test]
    public async Task RenewableUntilRequestedTime()
    {
        (TicketTimes times, Kerberos.TicketFlag flags) = Compute(
            KdcOptions.Renewable, s_now.AddDays(1), s_now.AddDays(2));

        await Assert.That(times.RenewTill).IsEqualTo(s_now.AddDays(2));
        await Assert.That(flags).IsEqualTo(Kerberos.TicketFlag.Renewable);
    }

    [Test]
    public async Task RenewableCappedAtMaximum()
    {
        (TicketTimes times, _) = Compute(KdcOptions.Renewable, s_now.AddDays(1), s_now.AddDays(30));

        await Assert.That(times.RenewTill).IsEqualTo(s_now.AddDays(7));
    }

    [Test]
    public async Task RenewableWithoutRTimeUsesMaximum()
    {
        (TicketTimes times, _) = Compute(KdcOptions.Renewable, s_now.AddDays(1));

        await Assert.That(times.RenewTill).IsEqualTo(s_now.AddDays(7));
    }

    [Test]
    public async Task RenewableOkWhenTillExceedsLifetime()
    {
        (TicketTimes times, Kerberos.TicketFlag flags) = Compute(KdcOptions.RenewableOk, s_now.AddDays(1));

        await Assert.That(times.End).IsEqualTo(s_now.AddHours(10));
        await Assert.That(times.RenewTill).IsEqualTo(s_now.AddDays(1));
        await Assert.That(flags).IsEqualTo(Kerberos.TicketFlag.Renewable);
    }

    [Test]
    public async Task RenewableOkNotNeededWithinLifetime()
    {
        (TicketTimes times, Kerberos.TicketFlag flags) = Compute(KdcOptions.RenewableOk, s_now.AddHours(1));

        await Assert.That(times.RenewTill).IsNull();
        await Assert.That(flags).IsEqualTo(Kerberos.TicketFlag.None);
    }

    [Test]
    public async Task NotRenewableWhenRenewTillIsNotAfterEnd()
    {
        (TicketTimes times, Kerberos.TicketFlag flags) = Compute(
            KdcOptions.Renewable, s_now.AddHours(5), s_now.AddHours(2));

        await Assert.That(times.RenewTill).IsNull();
        await Assert.That(flags).IsEqualTo(Kerberos.TicketFlag.None);
    }

    [Test]
    public async Task LimitedByTgt()
    {
        (TicketTimes times, Kerberos.TicketFlag flags) = Compute(
            KdcOptions.Renewable,
            s_now.AddDays(1),
            s_now.AddDays(5),
            maxEndTime: s_now.AddHours(3),
            maxRenewTill: s_now.AddDays(2));

        await Assert.That(times.End).IsEqualTo(s_now.AddHours(3));
        await Assert.That(times.RenewTill).IsEqualTo(s_now.AddDays(2));
        await Assert.That(flags).IsEqualTo(Kerberos.TicketFlag.Renewable);
    }

    [Test]
    public async Task NotRenewableWhenTgtIsNot()
    {
        // The TGS handler passes now as the renew-till limit for a TGT that is not renewable.
        (TicketTimes times, Kerberos.TicketFlag flags) = Compute(
            KdcOptions.Renewable,
            s_now.AddDays(1),
            s_now.AddDays(5),
            maxRenewTill: s_now);

        await Assert.That(times.RenewTill).IsNull();
        await Assert.That(flags).IsEqualTo(Kerberos.TicketFlag.None);
    }
}
