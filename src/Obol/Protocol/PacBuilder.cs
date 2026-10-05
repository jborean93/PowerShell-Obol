using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using Obol.Kerberos;
using KrbAuthorizationData = Kerberos.NET.Entities.KrbAuthorizationData;
using KrbGroupMembership = Kerberos.NET.Entities.Pac.GroupMembership;
using KrbPac = Kerberos.NET.Entities.PrivilegedAttributeCertificate;
using KrbPacClientInfo = Kerberos.NET.Entities.PacClientInfo;
using KrbPacLogonInfo = Kerberos.NET.Entities.Pac.PacLogonInfo;
using KrbSignatureMode = Kerberos.NET.Entities.SignatureMode;
using KrbUpnDomainInfo = Kerberos.NET.Entities.UpnDomainInfo;
using RpcFileTime = Kerberos.NET.Entities.Pac.RpcFileTime;

namespace Obol.Protocol;

/// <summary>Builds the public <see cref="Pac"/> from the AD-WIN2K-PAC authorization data of a ticket.</summary>
internal static class PacBuilder
{
    /// <summary>The high part of a FILETIME that means never.</summary>
    private const uint NeverHigh = 0x7FFFFFFF;

    /// <summary>The size of the PAC_INFO_BUFFER header of each buffer.</summary>
    private const int BufferHeaderSize = 16;

    /// <summary>Builds the PAC, the buffers are always listed and the known ones decoded when they parse.</summary>
    public static Pac Build(ReadOnlyMemory<byte> data)
    {
        (int version, PacBuffer[] buffers) = ParseBuffers(data);

        KrbPac? pac = null;
        try
        {
            pac = new KrbPac(
                new KrbAuthorizationData { Type = AuthorizationDataType.Win2kPac.ToKerberosNet(), Data = data },
                KrbSignatureMode.Kdc);
        }
        catch (Exception)
        {
            // A PAC Kerberos.NET cannot decode still shows its buffers.
        }

        return new Pac
        {
            Version = version,
            Buffer = buffers,
            LogonInfo = pac?.LogonInfo is KrbPacLogonInfo logon ? BuildLogonInfo(logon) : null,
            ClientInfo = pac?.ClientInformation is KrbPacClientInfo client
                ? new PacClientInfo(ToLocal(client.ClientId) ?? DateTime.MinValue, client.Name)
                : null,
            UpnDnsInfo = pac?.UpnDomainInformation is KrbUpnDomainInfo upn
                ? new PacUpnDnsInfo(upn.Upn, upn.Domain, upn.Flags.ToObol())
                : null,
        };
    }

    /// <summary>Reads the PACTYPE header and the PAC_INFO_BUFFER entries, MS-PAC 2.3 and 2.4.</summary>
    private static (int Version, PacBuffer[] Buffers) ParseBuffers(ReadOnlyMemory<byte> data)
    {
        ReadOnlySpan<byte> span = data.Span;
        if (span.Length < 8)
        {
            return (0, []);
        }

        uint count = BinaryPrimitives.ReadUInt32LittleEndian(span);
        int version = BinaryPrimitives.ReadInt32LittleEndian(span[4..]);
        List<PacBuffer> buffers = [];
        for (int i = 0; i < count; i++)
        {
            int offset = 8 + i * BufferHeaderSize;
            if (offset + BufferHeaderSize > span.Length)
            {
                break;
            }

            uint type = BinaryPrimitives.ReadUInt32LittleEndian(span[offset..]);
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(span[(offset + 4)..]);
            ulong start = BinaryPrimitives.ReadUInt64LittleEndian(span[(offset + 8)..]);
            byte[] bytes = start + size <= (ulong)span.Length
                ? span.Slice((int)start, (int)size).ToArray()
                : [];
            buffers.Add(new PacBuffer((PacBufferType)type, bytes));
        }

        return (version, [.. buffers]);
    }

    private static PacLogonInfo BuildLogonInfo(KrbPacLogonInfo logon) => new()
    {
        LogonTime = ToLocal(logon.LogonTime),
        LogoffTime = ToLocal(logon.LogoffTime),
        KickOffTime = ToLocal(logon.KickOffTime),
        PasswordLastSet = ToLocal(logon.PwdLastChangeTime),
        PasswordCanChange = ToLocal(logon.PwdCanChangeTime),
        PasswordMustChange = ToLocal(logon.PwdMustChangeTime),
        UserName = logon.UserName?.ToString() ?? "",
        UserDisplayName = logon.UserDisplayName?.ToString() ?? "",
        LogonScript = logon.LogonScript?.ToString() ?? "",
        ProfilePath = logon.ProfilePath?.ToString() ?? "",
        HomeDirectory = logon.HomeDirectory?.ToString() ?? "",
        HomeDrive = logon.HomeDrive?.ToString() ?? "",
        LogonCount = logon.LogonCount,
        BadPasswordCount = logon.BadPasswordCount,
        UserId = logon.UserId,
        PrimaryGroupId = logon.GroupId,
        GroupId = [.. (logon.GroupIds ?? []).Select(ToMembership)],
        UserFlag = logon.UserFlags.ToObol(),
        UserSessionKey = logon.UserSessionKey.ToArray(),
        ServerName = logon.ServerName?.ToString() ?? "",
        DomainName = logon.DomainName?.ToString() ?? "",
        DomainSid = logon.DomainSid?.Value ?? "",
        UserAccountControl = logon.UserAccountControl.ToObol(),
        ExtraSid = [.. (logon.ExtraIds ?? []).Select(e => new PacSidAttributes(
            e.ToSecurityIdentifier().Value, e.Attributes.ToObol()))],
        ResourceDomainSid = logon.ResourceDomainSid?.Value,
        ResourceGroupId = [.. (logon.ResourceGroupIds ?? []).Select(ToMembership)],
    };

    private static PacGroupMembership ToMembership(KrbGroupMembership group)
        => new(group.RelativeId, group.Attributes.ToObol());

    /// <summary>Converts a FILETIME to local time, null for the zero and never values.</summary>
    private static DateTime? ToLocal(RpcFileTime? time)
    {
        if (time is null || time.HighDateTime == NeverHigh || (time.HighDateTime == 0 && time.LowDateTime == 0))
        {
            return null;
        }

        return RpcFileTime.Convert(time.LowDateTime, time.HighDateTime).LocalDateTime;
    }
}
