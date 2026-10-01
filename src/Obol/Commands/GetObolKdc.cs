using System.Linq;
using System.Management.Automation;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.Get, "ObolKdc"
)]
[OutputType(typeof(ObolKdc))]
public sealed class GetObolKdc : PSCmdlet
{
    [Parameter(
        Position = 0
    )]
    [ValidateNotNullOrEmpty]
    [SupportsWildcards]
    public string[]? Realm { get; set; }

    [Parameter]
    [ValidateNotNullOrEmpty]
    public int[]? Port { get; set; }

    protected override void EndProcessing()
    {
        WildcardPattern[]? patterns = Realm?
            .Select(r => WildcardPattern.Get(r, WildcardOptions.IgnoreCase))
            .ToArray();
        foreach (ObolKdc kdc in ModuleSettings.GetFromTLS().Kdcs)
        {
            if (patterns is not null && !patterns.Any(p => p.IsMatch(kdc.Realm)))
            {
                continue;
            }
            if (Port is not null && !Port.Contains(kdc.Port))
            {
                continue;
            }

            WriteObject(kdc);
        }
    }
}
