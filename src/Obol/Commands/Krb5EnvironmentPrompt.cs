using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;

namespace Obol.Commands;

/// <summary>Adds the realm of a krb5 environment to the prompt function of the current runspace.</summary>
internal static class Krb5EnvironmentPrompt
{
    // The replacement is a closure over the original so it does not need a variable in the session. The prefix is
    // only colored when $PSStyle allows it, which also covers NO_COLOR.
    private const string SetScript = """
        param ($Label)

        $original = ${function:global:prompt}
        $replacement = {
            $prefix = if ($PSStyle.OutputRendering -eq 'PlainText') {
                $Label
            }
            else {
                "$($PSStyle.Foreground.Cyan)$Label$($PSStyle.Reset)"
            }
            $value = if ($original) { -join (& $original) } else { 'PS> ' }
            "$prefix $value"
        }.GetNewClosure()
        ${function:global:prompt} = $replacement

        $original, $replacement
        """;

    // Left alone if the prompt was replaced after entering, such as by a prompt theme or profile.
    private const string RestoreScript = """
        param ($Original, $Replacement)

        if ([object]::ReferenceEquals(${function:global:prompt}, $Replacement)) {
            if ($Original) {
                ${function:global:prompt} = $Original
            }
            else {
                Remove-Item -LiteralPath Function:\prompt
            }
        }
        """;

    /// <summary>Gets the label for the realms, the first realm and the number of other realms.</summary>
    public static string GetLabel(string[] realms)
    {
        string[] distinct = realms.Distinct().ToArray();
        return distinct.Length == 1 ? $"[{distinct[0]}]" : $"[{distinct[0]} +{distinct.Length - 1}]";
    }

    /// <summary>Replaces the global prompt function with one that starts with the label.</summary>
    /// <returns>The original prompt, null if there was none, and its replacement.</returns>
    public static (ScriptBlock? Original, ScriptBlock Replacement) Set(PSCmdlet cmdlet, string label)
    {
        Collection<PSObject> result = cmdlet.InvokeCommand.InvokeScript(
            useLocalScope: true,
            cmdlet.InvokeCommand.NewScriptBlock(SetScript),
            input: null,
            label);
        return (result[0]?.BaseObject as ScriptBlock, (ScriptBlock)result[1].BaseObject);
    }

    /// <summary>Restores the original prompt if the prompt is still the replacement.</summary>
    public static void Restore(PSCmdlet cmdlet, (ScriptBlock? Original, ScriptBlock Replacement) prompt)
    {
        cmdlet.InvokeCommand.InvokeScript(
            useLocalScope: true,
            cmdlet.InvokeCommand.NewScriptBlock(RestoreScript),
            input: null,
            prompt.Original,
            prompt.Replacement);
    }
}
