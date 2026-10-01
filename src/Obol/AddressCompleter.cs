using System;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Language;

namespace Obol;

/// <summary>Completes the well known addresses a KDC can listen on.</summary>
public sealed class AddressCompleter : IArgumentCompleter
{
    private static readonly (string Address, string ToolTip)[] s_knownAddresses =
    [
        ("127.0.0.1", "IPv4 loopback, only reachable from this host (default)"),
        ("::1", "IPv6 loopback, only reachable from this host"),
        ("0.0.0.0", "All IPv4 addresses"),
        ("::", "All IPv6 and IPv4 addresses"),
    ];

    public IEnumerable<CompletionResult> CompleteArgument(
        string commandName,
        string parameterName,
        string wordToComplete,
        CommandAst commandAst,
        IDictionary fakeBoundParameters)
    {
        string prefix = wordToComplete.Trim('\'', '"');
        foreach ((string address, string toolTip) in s_knownAddresses)
        {
            if (address.StartsWith(prefix, StringComparison.Ordinal))
            {
                yield return new CompletionResult(address, address, CompletionResultType.ParameterValue, toolTip);
            }
        }
    }
}
