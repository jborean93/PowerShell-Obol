using System.Management.Automation;
using System.Security;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.New, "ObolPrincipalSetting"
)]
[OutputType(typeof(ObolPrincipalSetting))]
public sealed class NewObolPrincipalSetting : PSCmdlet
{
    [Parameter]
    [ValidateNotNull]
    public SecureString? Password { get; set; }

    [Parameter]
    public ObolPrincipalFlag Flag { get; set; }

    [Parameter]
    [ValidateNotNull]
    public ObolEncryptionType[]? EncryptionType { get; set; }

    [Parameter]
    [ValidateNotNull]
    public string[]? Alias { get; set; }

    [Parameter]
    [ValidateRange(1, int.MaxValue)]
    public int? Rid { get; set; }

    protected override void EndProcessing()
    {
        WriteObject(new ObolPrincipalSetting
        {
            Password = Password,
            Flag = Flag,
            EncryptionType = EncryptionType,
            Alias = Alias,
            Rid = Rid,
        });
    }
}
