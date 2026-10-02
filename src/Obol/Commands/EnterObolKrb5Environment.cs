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

        // Only the current user can read the directory on Linux and macOS.
        DirectoryInfo directory = Directory.CreateTempSubdirectory("obol-");
        bool entered = false;
        try
        {
            string krb5Conf = Path.Combine(directory.FullName, "krb5.conf");
            File.WriteAllText(krb5Conf, Krb5Config.Create(_kdcs, Provider), new UTF8Encoding(false));

            // The ccache file is created by the client that first stores a ticket in it.
            List<KeyValuePair<string, string>> variables =
            [
                new("KRB5_CONFIG", krb5Conf),
                new("KRB5CCNAME", $"FILE:{Path.Combine(directory.FullName, "ccache")}"),
            ];
            if (ServicePrincipal.Length > 0)
            {
                string path = WriteKeytab(directory.FullName, "service.keytab", ServicePrincipal);
                variables.Add(new("KRB5_KTNAME", $"FILE:{path}"));
            }
            if (ClientPrincipal.Length > 0)
            {
                string path = WriteKeytab(directory.FullName, "client.keytab", ClientPrincipal);
                variables.Add(new("KRB5_CLIENT_KTNAME", $"FILE:{path}"));
            }

            Krb5Environment? environment = Krb5Environment.TryEnter(
                directory.FullName,
                variables,
                SetNativeEnvironment,
                Runspace.DefaultRunspace);
            if (environment is null)
            {
                ThrowTerminatingError(AlreadyEnteredError());
            }
            entered = true;
            WriteVerbose($"Entered the krb5 environment in '{directory.FullName}'");

            if (!NoPrompt)
            {
                string label = Krb5EnvironmentPrompt.GetLabel(_kdcs.Select(k => k.Realm).ToArray());
                environment!.Prompt = Krb5EnvironmentPrompt.Set(this, label);
            }
        }
        finally
        {
            if (!entered)
            {
                directory.Delete(recursive: true);
            }
        }
    }

    private static string WriteKeytab(string directory, string name, ObolPrincipal[] principals)
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

    private static ErrorRecord AlreadyEnteredError() => new(
        new InvalidOperationException(
            "A krb5 environment is already entered in this process, run Exit-ObolKrb5Environment first or set " +
            "the environment variables yourself with Export-ObolKrb5Config"),
        "Krb5EnvironmentAlreadyEntered",
        ErrorCategory.ResourceExists,
        null);
}
