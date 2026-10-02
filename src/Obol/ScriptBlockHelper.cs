using System;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Reflection;

namespace Obol;

/// <summary>Helpers for running a scriptblock given to a cmdlet like the call or dot-source operator would.</summary>
internal static class ScriptBlockHelper
{
    private static ConstructorInfo? s_parameterMetadataCtor;

    /// <summary>
    /// Creates a copy of the scriptblock with no session state affinity, so it runs in the scope it is invoked from.
    /// </summary>
    /// <remarks>
    /// The copy is created from the AST rather than the text so it keeps the file and position of the original for
    /// $PSScriptRoot, $MyInvocation and error messages.
    /// </remarks>
    public static ScriptBlock StripScriptBlockAffinity(ScriptBlock scriptBlock) => scriptBlock.Ast switch
    {
        ScriptBlockAst sba => sba.GetScriptBlock(),
        FunctionDefinitionAst fda => GetScriptBlockFromFunctionDefinitionAst(fda),
        _ => throw new RuntimeException($"Unexpected Ast type from ScriptBlock {scriptBlock.Ast.GetType().Name}."),
    };

    private static ScriptBlock GetScriptBlockFromFunctionDefinitionAst(FunctionDefinitionAst fda)
    {
        // There is no public API to get a ScriptBlock from a FunctionDefinitionAst, such as the one of
        // ${function:name}. fda.Body.GetScriptBlock() would lose the parameters and attributes of the function so
        // this uses the constructor PowerShell uses internally.
        if (s_parameterMetadataCtor is null)
        {
            Type providerType = typeof(FunctionDefinitionAst).Assembly.GetType(
                "System.Management.Automation.Language.IParameterMetadataProvider")
                ?? throw new RuntimeException("Could not find IParameterMetadataProvider type via reflection.");

            s_parameterMetadataCtor = typeof(ScriptBlock).GetConstructor(
                BindingFlags.NonPublic | BindingFlags.Instance,
                null,
                [providerType, typeof(bool)],
                null)
                ?? throw new RuntimeException(
                    "Could not find ScriptBlock IParameterMetadataProvider constructor via reflection.");
        }

        return (ScriptBlock)s_parameterMetadataCtor.Invoke([fda, fda.IsFilter]);
    }
}
