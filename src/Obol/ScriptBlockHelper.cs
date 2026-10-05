using System;
using System.Collections.Generic;
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

    /// <summary>
    /// Runs a scriptblock given to a cmdlet with arguments, like the call operator or, with
    /// <paramref name="dotSource"/>, the dot-source operator in the caller's scope. The streams of the scriptblock go
    /// through the cmdlet.
    /// </summary>
    /// <param name="cmdlet">The cmdlet the scriptblock was given to, its position is used for $MyInvocation.</param>
    /// <param name="scriptBlock">The scriptblock to run.</param>
    /// <param name="arguments">The arguments to pass, each is a separate argument.</param>
    /// <param name="dotSource">Whether to run the scriptblock in the caller's scope rather than a new one.</param>
    /// <param name="discardOutput">Whether to drop the output of the scriptblock rather than write it.</param>
    public static void Invoke(
        PSCmdlet cmdlet,
        ScriptBlock scriptBlock,
        object?[] arguments,
        bool dotSource,
        bool discardOutput = false)
    {
        // The scriptblock is copied without its session state affinity, so dot-sourcing it runs it in the caller's
        // scope. The parameters of the wrapper are not set in the caller's scope.
        ScriptBlock wrapper = CreateWrapper(cmdlet, dotSource ? TokenKind.Dot : TokenKind.Ampersand, discardOutput);
        object[] args = [StripScriptBlockAffinity(scriptBlock), arguments];

        // A steppable pipeline started with the cmdlet writes every stream through it, so redirection and the
        // common parameters of the cmdlet apply like they would to the scriptblock.
        using SteppablePipeline pipeline = wrapper.GetSteppablePipeline(CommandOrigin.Internal, args);
        pipeline.Begin(cmdlet);

        // Without input a pipeline still runs the process block once, like & { process { } } does.
        pipeline.Process();
        pipeline.End();
    }

    /// <summary>
    /// Creates <c>param ($ScriptBlock, $Arguments) &amp; $ScriptBlock @Arguments</c> at the cmdlet's position, piped
    /// to Out-Null when the output is discarded.
    /// </summary>
    /// <remarks>
    /// $MyInvocation in the scriptblock is created from the position of the command that invokes it, so it shows the
    /// line that called the cmdlet like <c>&amp; { ... }</c> would, rather than a position in generated text.
    /// </remarks>
    private static ScriptBlock CreateWrapper(PSCmdlet cmdlet, TokenKind invocationOperator, bool discardOutput)
    {
        // Only the first line of a command that spans several lines is known.
        InvocationInfo invocation = cmdlet.MyInvocation;
        string file = invocation.ScriptName;
        string line = invocation.Line;
        int lineNumber = Math.Max(invocation.ScriptLineNumber, 1);
        int column = Math.Max(invocation.OffsetInLine, 1);
        IScriptExtent extent = new ScriptExtent(
            new ScriptPosition(file, lineNumber, column, line),
            new ScriptPosition(file, lineNumber, Math.Max(line.Length + 1, column), line));

        ParameterAst[] parameters =
        [
            new(extent, new VariableExpressionAst(extent, "ScriptBlock", splatted: false), [], null),
            new(extent, new VariableExpressionAst(extent, "Arguments", splatted: false), [], null),
        ];
        CommandAst command = new(
            extent,
            [
                new VariableExpressionAst(extent, "ScriptBlock", splatted: false),
                new VariableExpressionAst(extent, "Arguments", splatted: true),
            ],
            invocationOperator,
            null);
        // A steppable pipeline needs a single pipeline, so the output is discarded by piping it to Out-Null.
        List<CommandBaseAst> commands = [command];
        if (discardOutput)
        {
            commands.Add(new CommandAst(
                extent,
                [new StringConstantExpressionAst(extent, @"Microsoft.PowerShell.Core\Out-Null",
                    StringConstantType.BareWord)],
                TokenKind.Unknown,
                null));
        }
        NamedBlockAst end = new(
            extent,
            TokenKind.End,
            new StatementBlockAst(extent, [new PipelineAst(extent, commands)], null),
            unnamed: true);

        return new ScriptBlockAst(
            extent,
            new ParamBlockAst(extent, [], parameters),
            beginBlock: null,
            processBlock: null,
            endBlock: end,
            dynamicParamBlock: null).GetScriptBlock();
    }

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
