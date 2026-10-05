using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management.Automation.Language;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using Microsoft.Win32;

namespace Obol;

/// <summary>
/// The Windows configuration of a MitRealm or DcLocator SSPI environment: registry keys for the Kerberos SSP or the
/// DNS client and, for DcLocator, the DNS and CLDAP listeners.
/// </summary>
/// <remarks>
/// Every key is created volatile so it is gone after a reboot if the process ends without removing it. Existing
/// configuration is never changed, a realm key or NRPT rule that already exists, even one an earlier Obol process left
/// behind, fails the setup with how to remove it.
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed partial class SspiMachineSetup
{
    private const string KerberosKey = @"SYSTEM\CurrentControlSet\Control\Lsa\Kerberos";
    private const string DomainsKey = KerberosKey + @"\Domains";
    private const string HostToRealmKey = KerberosKey + @"\HostToRealm";
    private const string NrptKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
    private const string NrptPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";

    /// <summary>The RealmFlags TcpSupported flag, without it the SSP only uses UDP for the realm.</summary>
    private const int RealmFlagTcpSupported = 0x2;

    /// <summary>The Version and ConfigOptions Add-DnsClientNrptRule writes for a rule with name servers.</summary>
    private const int NrptVersion = 2;
    private const int NrptConfigOptionsGenericDns = 0x8;

    /// <summary>The keys created under HKLM in the order they were created.</summary>
    private readonly List<string> _keys = [];
    private DcLocatorServer? _server;

    private SspiMachineSetup()
    {
    }

    /// <summary>Checks that none of the configuration a scope creates for the realms exists.</summary>
    /// <exception cref="SspiConflictException">Some of the configuration exists.</exception>
    public static void CheckConflicts(ObolSspiKdcScope scope, IEnumerable<string> realms)
    {
        List<string> conflicts = [];
        if (scope == ObolSspiKdcScope.DcLocator && GetPolicyNrptRules() is string[] policyRules)
        {
            // Even an empty policy key turns the local rules off.
            string rules = policyRules.Length == 0 ? "" : $" ({string.Join(", ", policyRules)})";
            conflicts.Add($"The Group Policy NRPT key HKLM\\{NrptPolicyKey}{rules} exists, Windows ignores every " +
                "local NRPT rule while it does.");
        }

        foreach (string realm in realms.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (scope == ObolSspiKdcScope.MitRealm)
            {
                CheckRealmKey(DomainsKey, realm, $"ksetup.exe /removerealm {Quote(realm)}", conflicts);
                CheckRealmKey(HostToRealmKey, realm, null, conflicts);
            }
            else
            {
                CheckNrptRules(realm, conflicts);
            }
        }

        if (conflicts.Count > 0)
        {
            throw new SspiConflictException(
                $"Cannot use scope {scope}, Obol does not change existing Windows configuration:\n" +
                string.Join("\n", conflicts.Select(c => $"- {c}")));
        }
    }

    /// <summary>Creates the configuration of a scope for the KDCs.</summary>
    /// <param name="scope">MitRealm or DcLocator.</param>
    /// <param name="kdcs">
    /// Each KDC with its realm, the address clients use and its transports. For DcLocator each KDC must have its own
    /// address.
    /// </param>
    /// <exception cref="SspiConflictException">Some of the configuration exists, nothing was changed.</exception>
    /// <exception cref="SspiKdcException">
    /// The configuration could not be created, what was created is removed.
    /// </exception>
    public static SspiMachineSetup Apply(
        ObolSspiKdcScope scope,
        IReadOnlyList<(ObolKdc Kdc, string Realm, IPAddress Address, ObolKdcTransport Transport)> kdcs)
    {
        Debug.Assert(scope is ObolSspiKdcScope.MitRealm or ObolSspiKdcScope.DcLocator);

        var realms = kdcs.GroupBy(k => k.Realm, StringComparer.OrdinalIgnoreCase).ToArray();
        CheckConflicts(scope, realms.Select(r => r.Key));

        SspiMachineSetup setup = new();
        try
        {
            if (scope == ObolSspiKdcScope.MitRealm)
            {
                foreach (var realm in realms)
                {
                    setup.AddRealm(realm.Key, [.. realm.Select(k => k.Address).Distinct()],
                        realm.All(k => k.Transport.HasFlag(ObolKdcTransport.Tcp)));
                }
            }
            else
            {
                DcLocatorDomain[] domains = [.. realms.Select(
                    r => DcLocatorDomain.Create(r.Key, [.. r.Select(k => k.Address).Distinct()]))];
                // Each KDC has its own address, a request is for the KDC on the address it was received on.
                Dictionary<IPAddress, ObolKdc> kdcByAddress = kdcs
                    .DistinctBy(k => k.Kdc)
                    .ToDictionary(k => k.Address, k => k.Kdc);
                setup._server = DcLocatorServer.Start(
                    domains,
                    e => kdcByAddress.GetValueOrDefault(e.LocalAddress)?.OnLocatorExchange(e));
                foreach (DcLocatorDomain domain in domains)
                {
                    setup.AddNrptRule(domain);
                }

                // A lookup made before the rule existed may have cached that the realm names do not exist.
                FlushDnsCache();
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or SecurityException)
        {
            setup.TryRemove();
            throw SspiKdcException.Create($"Setting up scope {scope}", e);
        }
        catch
        {
            setup.TryRemove();
            throw;
        }

        return setup;
    }

    /// <summary>Removes the keys created and stops the DC locator listeners.</summary>
    /// <exception cref="SspiKdcException">Some keys could not be removed, the rest was still removed.</exception>
    public void Remove()
    {
        List<string> failures = [];
        bool nrpt = false;
        for (int i = _keys.Count - 1; i >= 0; i--)
        {
            string key = _keys[i];
            nrpt |= key.StartsWith(NrptKey, StringComparison.OrdinalIgnoreCase);
            try
            {
                Registry.LocalMachine.DeleteSubKeyTree(key, throwOnMissingSubKey: false);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or SecurityException)
            {
                failures.Add($"HKLM\\{key}: {e.Message}");
            }
        }
        _keys.Clear();

        if (nrpt)
        {
            FlushDnsCache();
        }

        // Stopped after the NRPT rule is removed so no lookup is sent to a closed port.
        _server?.Dispose();
        _server = null;

        if (failures.Count > 0)
        {
            throw SspiKdcException.Create(
                "Failed to remove the volatile registry keys, they are removed on the next reboot:\n" +
                string.Join("\n", failures));
        }
    }

    private void TryRemove()
    {
        try
        {
            Remove();
        }
        catch (SspiKdcException)
        {
            // The original failure is the one to report.
        }
    }

    /// <summary>Adds the realm and its KDCs like ksetup /addkdc and maps the hosts under the realm to it.</summary>
    private void AddRealm(string realm, IPAddress[] addresses, bool tcp)
    {
        using (RegistryKey key = CreateVolatileKey(DomainsKey, realm))
        {
            key.SetValue("KdcNames", addresses.Select(a => a.ToString()).ToArray(), RegistryValueKind.MultiString);
            key.SetValue("RealmFlags", tcp ? RealmFlagTcpSupported : 0, RegistryValueKind.DWord);
        }

        // The [domain_realm] mapping a krb5 environment writes, web.example.test is in EXAMPLE.TEST.
        string domain = realm.ToLowerInvariant();
        using (RegistryKey key = CreateVolatileKey(HostToRealmKey, realm))
        {
            key.SetValue("SpnMappings", new[] { $".{domain}", domain }, RegistryValueKind.MultiString);
        }
    }

    /// <summary>
    /// Adds an NRPT rule like Add-DnsClientNrptRule that sends the realm names to the DNS listeners on the KDC
    /// addresses.
    /// </summary>
    private void AddNrptRule(DcLocatorDomain realm)
    {
        string domain = realm.DnsName;
        string servers = string.Join(";", realm.Kdcs.Select(k => k.Address).Distinct());
        using RegistryKey key = CreateVolatileKey(NrptKey, $"{{{Guid.NewGuid()}}}");
        key.SetValue("Version", NrptVersion, RegistryValueKind.DWord);
        key.SetValue("ConfigOptions", NrptConfigOptionsGenericDns, RegistryValueKind.DWord);
        key.SetValue("Name", new[] { domain, $".{domain}" }, RegistryValueKind.MultiString);
        key.SetValue("GenericDNSServers", servers, RegistryValueKind.String);
        key.SetValue("IPSECCARestriction", "", RegistryValueKind.String);
        key.SetValue("DisplayName", "", RegistryValueKind.String);
        key.SetValue("Comment", $"Obol DC locator for {domain}", RegistryValueKind.String);
    }

    /// <summary>Creates a volatile subkey that must not exist, the parent is created if needed.</summary>
    private RegistryKey CreateVolatileKey(string parentPath, string name)
    {
        // A missing parent is created persistent, a volatile one would stop ksetup or Windows creating persistent
        // keys under it until the next reboot.
        using RegistryKey parent = Registry.LocalMachine.CreateSubKey(parentPath, writable: true);
        string path = $"{parentPath}\\{name}";
        if (parent.OpenSubKey(name) is RegistryKey existing)
        {
            existing.Dispose();
            throw new SspiConflictException($"The registry key HKLM\\{path} already exists");
        }

        RegistryKey key = parent.CreateSubKey(name, writable: true, RegistryOptions.Volatile);
        _keys.Add(path);
        return key;
    }

    private static void CheckRealmKey(string parentPath, string realm, string? removeCommand, List<string> conflicts)
    {
        string path = $"{parentPath}\\{realm}";
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(path);
        if (key is null)
        {
            return;
        }

        string removeItem = $"Remove-Item -LiteralPath {Quote($"HKLM:\\{path}")} -Recurse";
        string remove = removeCommand is null ? removeItem : $"{removeCommand}, or {removeItem}";
        conflicts.Add($"The registry key HKLM\\{path} already exists. Remove it with {remove}.");
    }

    private static void CheckNrptRules(string realm, List<string> conflicts)
    {
        using RegistryKey? rules = Registry.LocalMachine.OpenSubKey(NrptKey);
        if (rules is null)
        {
            return;
        }

        string domain = realm.ToLowerInvariant();
        foreach (string name in rules.GetSubKeyNames())
        {
            using RegistryKey? rule = rules.OpenSubKey(name);
            if (rule?.GetValue("Name") is not string[] namespaces ||
                !namespaces.Any(n => n.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                    n.Equals($".{domain}", StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            conflicts.Add($"The NRPT rule {name} for {string.Join(", ", namespaces)} already exists. Remove it " +
                $"with Remove-DnsClientNrptRule -Name {Quote(name)} -Force.");
        }
    }

    /// <summary>Quotes a value as a single quoted PowerShell string for the commands in the errors.</summary>
    private static string Quote(string value) => $"'{CodeGeneration.EscapeSingleQuotedStringContent(value)}'";

    /// <summary>Gets the Group Policy NRPT rules, null if the policy key does not exist.</summary>
    private static string[]? GetPolicyNrptRules()
    {
        using RegistryKey? rules = Registry.LocalMachine.OpenSubKey(NrptPolicyKey);
        return rules?.GetSubKeyNames();
    }

    /// <summary>Flushes the DNS client cache like ipconfig /flushdns.</summary>
    private static void FlushDnsCache() => DnsFlushResolverCache();

    [LibraryImport("dnsapi.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DnsFlushResolverCache();
}
