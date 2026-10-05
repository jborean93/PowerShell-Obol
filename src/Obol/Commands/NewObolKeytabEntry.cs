using System;
using System.Management.Automation;
using System.Security;
using Obol.Kerberos;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.New, "ObolKeytabEntry",
    DefaultParameterSetName = PasswordParameterSet
)]
[OutputType(typeof(ObolKeytabEntry))]
public sealed class NewObolKeytabEntry : PSCmdlet
{
    private const string PasswordParameterSet = "Password";
    private const string KeyParameterSet = "Key";
    private const string PrincipalParameterSet = "Principal";

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = KeyParameterSet
    )]
    [ValidateNotNullOrEmpty]
    public string Name { get; set; } = "";

    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        ParameterSetName = KeyParameterSet
    )]
    [ValidateNotNullOrEmpty]
    public string? Realm { get; set; }

    [Parameter(
        Mandatory = true,
        ParameterSetName = PasswordParameterSet
    )]
    [ValidateNotNull]
    public SecureString? Password { get; set; }

    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [ValidateNotNull]
    public string? Salt { get; set; }

    [Parameter(
        Mandatory = true,
        ParameterSetName = KeyParameterSet
    )]
    [ValidateNotNullOrEmpty]
    public byte[] Key { get; set; } = [];

    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        Mandatory = true,
        ParameterSetName = KeyParameterSet
    )]
    [ValidateNotNull]
    [ValidateSet(typeof(SupportedEncryptionTypeValues))]
    public EncryptionType[]? EncryptionType { get; set; }

    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        ParameterSetName = KeyParameterSet
    )]
    [ValidateRange(0, int.MaxValue)]
    public int Kvno { get; set; } = 1;

    [Parameter(
        Mandatory = true,
        ValueFromPipeline = true,
        ParameterSetName = PrincipalParameterSet
    )]
    [ValidateNotNull]
    public ObolPrincipal[] Principal { get; set; } = [];

    protected override void ProcessRecord()
    {
        if (ParameterSetName == PrincipalParameterSet)
        {
            // The principal's current keys under its name and aliases, like Export-ObolKeytab writes them.
            DateTime now = DateTime.UtcNow;
            foreach (ObolPrincipal principal in Principal)
            {
                if (principal is not null)
                {
                    WriteObject(Keytab.GetEntries(principal, now), enumerateCollection: true);
                }
            }
            return;
        }

        string[]? components = PrincipalCommandHelper.ParseNameWithRealm(Name, Realm, out string realm,
            out ErrorRecord? error);
        if (components is null)
        {
            ThrowTerminatingError(error!);
            return;
        }

        EncryptionType[]? etypes = PrincipalCommandHelper.CheckEncryptionTypes(EncryptionType, out error);
        if (error is not null)
        {
            ThrowTerminatingError(error);
            return;
        }

        DateTime timestamp = DateTime.UtcNow;
        if (ParameterSetName == KeyParameterSet)
        {
            WriteKeyEntry(realm, components, etypes!, timestamp);
            return;
        }

        if (Password!.Length == 0)
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("The password must not be empty"),
                "EmptyPassword",
                ErrorCategory.InvalidArgument,
                null));
            return;
        }

        // AES256 and AES128 like a new principal, MIT ktutil and ktpass /crypto All.
        etypes ??= PrincipalStore.DefaultEncryptionTypes;
        string salt = Salt ?? PrincipalStore.GetDefaultSalt(realm, components);
        byte[][] keys = PrincipalStore.DeriveKeys(Password, salt, etypes);
        for (int i = 0; i < etypes.Length; i++)
        {
            WriteObject(new ObolKeytabEntry(realm, components, PrincipalNameType.Principal, timestamp, Kvno,
                etypes[i], keys[i]));
        }
    }

    private void WriteKeyEntry(string realm, string[] components, EncryptionType[] etypes, DateTime timestamp)
    {
        if (etypes.Length != 1)
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("EncryptionType must be a single value with Key"),
                "InvalidEncryptionType",
                ErrorCategory.InvalidArgument,
                etypes));
            return;
        }

        int size = PrincipalStore.GetKeySize(etypes[0]);
        if (Key.Length != size)
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException($"The {etypes[0]} key must be {size} bytes, got {Key.Length}"),
                "InvalidKeyLength",
                ErrorCategory.InvalidArgument,
                Key));
            return;
        }

        WriteObject(new ObolKeytabEntry(realm, components, PrincipalNameType.Principal, timestamp, Kvno, etypes[0],
            (byte[])Key.Clone()));
    }
}
