using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.Enter, "ObolKrb5Environment",
    SupportsShouldProcess = true
)]
public sealed class EnterObolKrb5Environment : PSCmdlet
{
    private readonly List<ObolKdc> _kdcs = [];

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true
    )]
    [ValidateNotNull]
    public ObolKdc[] Kdc { get; set; } = [];

    [Parameter]
    public ObolKrb5Provider Provider { get; set; } = ObolKrb5Provider.Default;

    [Parameter]
    [ValidateNotNull]
    public ObolPrincipal[] ServicePrincipal { get; set; } = [];

    [Parameter]
    [ValidateNotNull]
    public ObolPrincipal[] ClientPrincipal { get; set; } = [];

    [Parameter]
    public SwitchParameter SetNativeEnvironment { get; set; }

    [Parameter]
    public SwitchParameter NoPrompt { get; set; }

    protected override void BeginProcessing()
    {
        if (Krb5Config.CheckProvider(Provider) is ErrorRecord error)
        {
            ThrowTerminatingError(error);
        }

        // Checked again when entering, this avoids collecting the KDCs when it would fail anyway.
        if (Krb5Environment.Current is not null)
        {
            ThrowTerminatingError(AlreadyEnteredError());
        }
    }

    protected override void ProcessRecord()
    {
        foreach (ObolKdc kdc in Kdc)
        {
            if (Krb5Config.CheckKdc(kdc) is ErrorRecord error)
            {
                WriteError(error);
                continue;
            }
            _kdcs.Add(kdc);
        }
    }

    protected override void EndProcessing()
    {
        // Nothing is changed if every KDC failed.
        if (_kdcs.Count == 0)
        {
            return;
        }

        if (!ShouldProcess(
            "process environment",
            $"Set the krb5 environment variables for {string.Join(", ", _kdcs)}"))
        {
            return;
        }

        Enter(this, _kdcs, Provider, ServicePrincipal, ClientPrincipal, SetNativeEnvironment, setPrompt: !NoPrompt);
    }

    /// <summary>Writes the files, sets the environment variables and optionally the prompt.</summary>
    /// <param name="cmdlet">The cmdlet to write to and throw the terminating errors of.</param>
    /// <param name="kdcs">The KDCs to use, each checked with <see cref="Krb5Config.CheckKdc"/>.</param>
    /// <param name="provider">The Kerberos implementation the krb5.conf is for.</param>
    /// <param name="servicePrincipals">The principals for KRB5_KTNAME, not set if empty.</param>
    /// <param name="clientPrincipals">The principals for KRB5_CLIENT_KTNAME, not set if empty.</param>
    /// <param name="setNativeEnvironment">Also set the C library's environment on Linux and macOS.</param>
    /// <param name="setPrompt">Add the realm to the prompt of the current runspace.</param>
    internal static Krb5Environment Enter(
        PSCmdlet cmdlet,
        IReadOnlyList<ObolKdc> kdcs,
        ObolKrb5Provider provider,
        IReadOnlyCollection<ObolPrincipal> servicePrincipals,
        IReadOnlyCollection<ObolPrincipal> clientPrincipals,
        bool setNativeEnvironment,
        bool setPrompt)
    {
        // Only the current user can read the directory on Linux and macOS.
        DirectoryInfo directory = Directory.CreateTempSubdirectory("obol-");
        Krb5Environment? environment = null;
        try
        {
            string krb5Conf = Path.Combine(directory.FullName, "krb5.conf");
            File.WriteAllText(krb5Conf, Krb5Config.Create(kdcs, provider), new UTF8Encoding(false));

            // The ccache file is created by the client that first stores a ticket in it.
            List<KeyValuePair<string, string>> variables =
            [
                new("KRB5_CONFIG", krb5Conf),
                new("KRB5CCNAME", $"FILE:{Path.Combine(directory.FullName, "ccache")}"),
            ];
            if (servicePrincipals.Count > 0)
            {
                string path = WriteKeytab(directory.FullName, "service.keytab", servicePrincipals);
                variables.Add(new("KRB5_KTNAME", $"FILE:{path}"));
            }
            if (clientPrincipals.Count > 0)
            {
                string path = WriteKeytab(directory.FullName, "client.keytab", clientPrincipals);
                variables.Add(new("KRB5_CLIENT_KTNAME", $"FILE:{path}"));
            }

            environment = Krb5Environment.TryEnter(
                directory.FullName,
                variables,
                setNativeEnvironment,
                Runspace.DefaultRunspace);
            if (environment is null)
            {
                cmdlet.ThrowTerminatingError(AlreadyEnteredError());
            }
            cmdlet.WriteVerbose($"Entered the krb5 environment in '{directory.FullName}'");

            if (setPrompt)
            {
                string label = EnvironmentPrompt.GetLabel(kdcs.Select(k => k.Realm).ToArray());
                environment.Prompt = EnvironmentPrompt.Set(cmdlet, label, "Cyan");
            }
        }
        finally
        {
            if (environment is null)
            {
                directory.Delete(recursive: true);
            }
        }

        return environment;
    }

    private static string WriteKeytab(string directory, string name, IEnumerable<ObolPrincipal> principals)
    {
        KeytabBuilder keytab = new();
        keytab.Add(principals);

        ArrayBufferWriter<byte> data = new();
        try
        {
            data.Write(Keytab.Header);
            keytab.Write(data);

            string path = Path.Combine(directory, name);
            FileStreamOptions options = new()
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }
            using FileStream stream = new(path, options);
            stream.Write(data.WrittenSpan);
            return path;
        }
        finally
        {
            // Clear zeroes the written bytes so the keys do not stay in memory.
            data.Clear();
        }
    }

    internal static ErrorRecord AlreadyEnteredError() => new(
        new InvalidOperationException(
            "A krb5 environment is already entered in this process, run Exit-ObolKrb5Environment first or set " +
            "the environment variables yourself with Export-ObolKrb5Config"),
        "Krb5EnvironmentAlreadyEntered",
        ErrorCategory.ResourceExists,
        null);
}
