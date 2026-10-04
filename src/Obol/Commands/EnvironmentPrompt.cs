using System.Collections;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;

namespace Obol.Commands;

/// <summary>Adds a label for an entered environment to the prompt function of the current runspace.</summary>
/// <remarks>
/// The krb5 and SSPI environments can both be entered and exited in any order, so each replacement wraps the prompt
/// that was there before it. An exited environment's replacement passes the inner prompt through unchanged, so its
/// label goes away even when another replacement was put on top of it and it cannot be removed.
/// </remarks>
internal static class EnvironmentPrompt
{
    // The replacement is a closure over the original and the state so it does not need a variable in the session.
    // The prefix is only colored when $PSStyle allows it, which also covers NO_COLOR.
    private const string SetScript = """
        param ($Label, $Color)

        $original = ${function:global:prompt}
        $state = @{ Active = $true }
        $replacement = {
            $value = if ($original) { -join (& $original) } else { 'PS> ' }
            if (-not $state.Active) {
                return $value
            }

            $prefix = if ($PSStyle.OutputRendering -eq 'PlainText') {
                $Label
            }
            else {
                "$($PSStyle.Foreground.$Color)$Label$($PSStyle.Reset)"
            }
            "$prefix $value"
        }.GetNewClosure()
        ${function:global:prompt} = $replacement

        $original, $replacement, $state
        """;

    // Left alone if the prompt was replaced after entering, such as by a prompt theme, a profile or the other
    // environment, the replacement is inactive so it only passes the inner prompt through.
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
    /// <param name="cmdlet">The cmdlet whose runspace's prompt is changed.</param>
    /// <param name="label">The text to put before the prompt.</param>
    /// <param name="color">The name of the <c>$PSStyle.Foreground</c> color of the label.</param>
    public static Handle Set(PSCmdlet cmdlet, string label, string color)
    {
        Collection<PSObject> result = cmdlet.InvokeCommand.InvokeScript(
            useLocalScope: true,
            cmdlet.InvokeCommand.NewScriptBlock(SetScript),
            input: null,
            label,
            color);
        return new(
            result[0]?.BaseObject as ScriptBlock,
            (ScriptBlock)result[1].BaseObject,
            (Hashtable)result[2].BaseObject);
    }

    /// <summary>
    /// Removes the label and restores the original prompt if the prompt is still the replacement. Must be called
    /// from the runspace that set it.
    /// </summary>
    public static void Restore(PSCmdlet cmdlet, Handle prompt)
    {
        prompt.Deactivate();
        cmdlet.InvokeCommand.InvokeScript(
            useLocalScope: true,
            cmdlet.InvokeCommand.NewScriptBlock(RestoreScript),
            input: null,
            prompt.Original,
            prompt.Replacement);
    }

    /// <summary>A prompt replacement set by <see cref="Set"/>.</summary>
    /// <param name="Original">The prompt before it was changed, null if there was none.</param>
    /// <param name="Replacement">The prompt function that adds the label.</param>
    /// <param name="State">The state the replacement reads, shared with the closure.</param>
    public sealed record Handle(ScriptBlock? Original, ScriptBlock Replacement, Hashtable State)
    {
        /// <summary>
        /// Stops the replacement adding the label, it then passes the inner prompt through. Safe from any thread,
        /// such as when the environment is exited as its runspace closes.
        /// </summary>
        public void Deactivate()
        {
            lock (State.SyncRoot)
            {
                State["Active"] = false;
            }
        }
    }
}
