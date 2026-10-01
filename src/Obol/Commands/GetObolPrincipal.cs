using System.Linq;
using System.Management.Automation;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.Get, "ObolPrincipal"
)]
[OutputType(typeof(ObolPrincipal))]
public sealed class GetObolPrincipal : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        ValueFromPipeline = true
    )]
    [ValidateNotNull]
    public ObolKdc[] Kdc { get; set; } = [];

    [Parameter(
        Position = 0
    )]
    [ValidateNotNullOrEmpty]
    [SupportsWildcards]
    public string[]? Name { get; set; }

    /// <summary>Matches the name or an alias, with or without the realm.</summary>
    private static bool IsMatch(WildcardPattern pattern, ObolPrincipal principal)
        => principal.Alias.Prepend(principal.Name).Any(
            n => pattern.IsMatch(n) || pattern.IsMatch($"{n}@{principal.Realm}"));

    protected override void ProcessRecord()
    {
        // Matching is case insensitive like other Get commands, even if the KDC matches names case sensitively.
        WildcardPattern[]? patterns = Name?
            .Select(n => WildcardPattern.Get(n, WildcardOptions.IgnoreCase))
            .ToArray();
        foreach (ObolKdc kdc in Kdc)
        {
            foreach (ObolPrincipal principal in kdc.Store.Principals)
            {
                if (patterns is not null && !patterns.Any(p => IsMatch(p, principal)))
                {
                    continue;
                }

                WriteObject(principal);
            }
        }
    }
}
