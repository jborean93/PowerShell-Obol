using System;

namespace Obol.Protocol;

/// <summary>The start, end and renew-till times of a ticket.</summary>
internal readonly record struct TicketTimes(DateTimeOffset Start, DateTimeOffset End, DateTimeOffset? RenewTill);
