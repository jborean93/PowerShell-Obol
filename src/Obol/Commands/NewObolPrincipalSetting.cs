using System.Management.Automation;
using System.Security;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.New, "ObolPrincipalSetting",
    DefaultParameterSetName = RandomParameterSet
)]
[OutputType(typeof(ObolPrincipalSetting))]
public sealed class NewObolPrincipalSetting : PSCmdlet
{
    // The sets follow where the keys come from like New-ObolPrincipal. A setting is still checked when it is used
    // as one cast from a hashtable skips parameter binding.
    private const string RandomParameterSet = "Random";
    private const string PasswordParameterSet = "Password";
    private const string KeyParameterSet = "Key";

    [Parameter(
        Mandatory = true,
        ParameterSetName = PasswordParameterSet
    )]
    [ValidateNotNull]
    public SecureString? Password { get; set; }

    [Parameter(
        ParameterSetName = RandomParameterSet
    )]
    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        ParameterSetName = KeyParameterSet
    )]
    public ObolPrincipalFlag Flag { get; set; }

    [Parameter(
        ParameterSetName = RandomParameterSet
    )]
    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [ValidateNotNull]
    public ObolEncryptionType[]? EncryptionType { get; set; }

    [Parameter(
        ParameterSetName = RandomParameterSet
    )]
    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        ParameterSetName = KeyParameterSet
    )]
    [ValidateNotNull]
    public string[]? Alias { get; set; }

    [Parameter(
        ParameterSetName = RandomParameterSet
    )]
    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        ParameterSetName = KeyParameterSet
    )]
    [ValidateRange(1, int.MaxValue)]
    public int? Rid { get; set; }

    [Parameter(
        Mandatory = true,
        ParameterSetName = KeyParameterSet
    )]
    [ValidateNotNull]
    public ObolKeytabEntry[]? Key { get; set; }

    [Parameter(
        ParameterSetName = RandomParameterSet
    )]
    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        ParameterSetName = KeyParameterSet
    )]
    [ValidateRange(0, int.MaxValue)]
    public int? Kvno { get; set; }

    [Parameter(
        ParameterSetName = PasswordParameterSet
    )]
    [Parameter(
        ParameterSetName = KeyParameterSet
    )]
    [ValidateNotNull]
    public string? Salt { get; set; }

    protected override void EndProcessing()
    {
        WriteObject(new ObolPrincipalSetting
        {
            Password = Password,
            Flag = Flag,
            EncryptionType = EncryptionType,
            Alias = Alias,
            Rid = Rid,
            Key = Key,
            Kvno = Kvno,
            Salt = Salt,
        });
    }
}
