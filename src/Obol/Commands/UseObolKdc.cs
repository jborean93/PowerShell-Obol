using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Net;
using Obol.Protocol;

namespace Obol.Commands;

[Cmdlet(
    VerbsOther.Use, "ObolKdc",
    DefaultParameterSetName = StartParameterSet
)]
public sealed class UseObolKdc : PSCmdlet
{
    private const string StartParameterSet = "Start";
    private const string KdcParameterSet = "Kdc";

    private readonly List<ObolKdc> _kdcs = [];

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = StartParameterSet
    )]
    [ValidateNotNullOrEmpty]
    public string Realm { get; set; } = "";

    [Parameter(
        Mandatory = true,
        ValueFromPipeline = true,
        ParameterSetName = KdcParameterSet
    )]
    [ValidateNotNull]
    public ObolKdc[] Kdc { get; set; } = [];

    [Parameter(
        Mandatory = true,
        Position = 1,
        ParameterSetName = StartParameterSet
    )]
    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = KdcParameterSet
    )]
    public ScriptBlock? ScriptBlock { get; set; }

    [Parameter(ParameterSetName = StartParameterSet)]
    [ValidateNotNull]
    [ArgumentCompleter(typeof(AddressCompleter))]
    public IPAddress Address { get; set; } = IPAddress.Loopback;

    [Parameter(ParameterSetName = StartParameterSet)]
    [ValidateRange(0, IPEndPoint.MaxPort)]
    public int Port { get; set; }

    [Parameter(ParameterSetName = StartParameterSet)]
    public ObolKdcTransport Transport { get; set; } = ObolKdcTransport.Tcp | ObolKdcTransport.Udp;

    [Parameter(ParameterSetName = StartParameterSet)]
    [ValidateRange(1, KdcListener.MaxUdpPayloadSize)]
    public int MaxUdpReplySize { get; set; } = KdcListener.DefaultMaxUdpReplySize;

    [Parameter(ParameterSetName = StartParameterSet)]
    public SwitchParameter CaseInsensitivePrincipal { get; set; }

    [Parameter(ParameterSetName = StartParameterSet)]
    [ValidateNotNullOrEmpty]
    public string? DomainSid { get; set; }

    [Parameter(ParameterSetName = StartParameterSet)]
    [ValidateNotNull]
    public IDictionary? Principal { get; set; }

    [Parameter]
    public ObolKrb5Provider Provider { get; set; } = ObolKrb5Provider.Default;

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string[] ServicePrincipal { get; set; } = [];

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string[] ClientPrincipal { get; set; } = [];

    [Parameter]
    public SwitchParameter SetNativeEnvironment { get; set; }

    [Parameter]
    public SwitchParameter NoNewScope { get; set; }

    protected override void BeginProcessing()
    {
        if (Krb5Config.CheckProvider(Provider) is ErrorRecord error)
        {
            ThrowTerminatingError(error);
        }

        // Checked before a KDC is started, Enter checks it again.
        if (Krb5Environment.Current is not null)
        {
            ThrowTerminatingError(EnterObolKrb5Environment.AlreadyEnteredError());
        }
    }

    protected override void ProcessRecord()
    {
        // The scriptblock only runs once all KDCs are received, a KDC that cannot be used stops it from running.
        foreach (ObolKdc kdc in Kdc)
        {
            if (Krb5Config.CheckKdc(kdc) is ErrorRecord error)
            {
                ThrowTerminatingError(error);
            }
            _kdcs.Add(kdc);
        }
    }

    protected override void EndProcessing()
    {
        Debug.Assert(ScriptBlock is not null);

        ObolKdc? started = null;
        try
        {
            if (ParameterSetName == StartParameterSet)
            {
                started = StartObolKdc.Start(
                    this,
                    Realm,
                    Address,
                    Port,
                    Transport,
                    MaxUdpReplySize,
                    CaseInsensitivePrincipal,
                    DomainSid,
                    Principal);
                _kdcs.Add(started);

                // Checked after starting as a realm Start-ObolKdc accepts may not fit in a krb5.conf.
                if (Krb5Config.CheckKdc(started) is ErrorRecord error)
                {
                    ThrowTerminatingError(error);
                }
            }
            else if (_kdcs.Count == 0)
            {
                ThrowTerminatingError(new ErrorRecord(
                    new ArgumentException("No KDC was given to -Kdc"),
                    "NoKdc",
                    ErrorCategory.InvalidArgument,
                    null));
            }

            List<ObolPrincipal> service = FindPrincipals(ServicePrincipal);
            List<ObolPrincipal> client = FindPrincipals(ClientPrincipal);

            // The prompt is not shown while the scriptblock runs, so it is left alone.
            Krb5Environment environment = EnterObolKrb5Environment.Enter(
                this,
                _kdcs,
                Provider,
                service,
                client,
                SetNativeEnvironment,
                setPrompt: false);
            try
            {
                Invoke(ScriptBlock);
            }
            finally
            {
                ExitObolKrb5Environment.Exit(this, environment);
            }
        }
        finally
        {
            started?.Dispose();
        }
    }

    /// <summary>Runs the scriptblock with the KDCs as arguments, like the call or dot-source operator.</summary>
    private void Invoke(ScriptBlock scriptBlock)
    {
        // The scriptblock is copied without its session state affinity, so -NoNewScope dot-sources it into the
        // caller's scope. Each KDC is a separate argument. The parameters of the wrapper are not set in the caller's
        // scope.
        ScriptBlock wrapper = CreateWrapper(NoNewScope ? TokenKind.Dot : TokenKind.Ampersand);
        object[] args =
        [
            ScriptBlockHelper.StripScriptBlockAffinity(scriptBlock),
            _kdcs.ToArray(),
        ];

        // A steppable pipeline started with this cmdlet writes every stream through it, so redirection and the
        // common parameters of this cmdlet apply like they would to the scriptblock.
        using SteppablePipeline pipeline = wrapper.GetSteppablePipeline(CommandOrigin.Internal, args);
        pipeline.Begin(this);

        // Without input a pipeline still runs the process block once, like & { process { } } does.
        pipeline.Process();
        pipeline.End();
    }

    /// <summary>Creates <c>param ($ScriptBlock, $Kdc) &amp; $ScriptBlock @Kdc</c> at this cmdlet's position.</summary>
    /// <remarks>
    /// $MyInvocation in the scriptblock is created from the position of the command that invokes it, so it shows the
    /// line that called this cmdlet like <c>&amp; { ... }</c> would, rather than a position in generated text.
    /// </remarks>
    private ScriptBlock CreateWrapper(TokenKind invocationOperator)
    {
        // Only the first line of a command that spans several lines is known.
        string file = MyInvocation.ScriptName;
        string line = MyInvocation.Line;
        int lineNumber = Math.Max(MyInvocation.ScriptLineNumber, 1);
        int column = Math.Max(MyInvocation.OffsetInLine, 1);
        IScriptExtent extent = new ScriptExtent(
            new ScriptPosition(file, lineNumber, column, line),
            new ScriptPosition(file, lineNumber, Math.Max(line.Length + 1, column), line));

        ParameterAst[] parameters =
        [
            new(extent, new VariableExpressionAst(extent, "ScriptBlock", splatted: false), [], null),
            new(extent, new VariableExpressionAst(extent, "Kdc", splatted: false), [], null),
        ];
        CommandAst command = new(
            extent,
            [
                new VariableExpressionAst(extent, "ScriptBlock", splatted: false),
                new VariableExpressionAst(extent, "Kdc", splatted: true),
            ],
            invocationOperator,
            null);
        NamedBlockAst end = new(
            extent,
            TokenKind.End,
            new StatementBlockAst(extent, [new PipelineAst(extent, command)], null),
            unnamed: true);

        return new ScriptBlockAst(
            extent,
            new ParamBlockAst(extent, [], parameters),
            beginBlock: null,
            processBlock: null,
            endBlock: end,
            dynamicParamBlock: null).GetScriptBlock();
    }

    /// <summary>Finds principals by name, a name without a realm is in the realm of the first KDC.</summary>
    private List<ObolPrincipal> FindPrincipals(string[] names)
    {
        List<ObolPrincipal> principals = [];
        foreach (string name in names)
        {
            if (!PrincipalName.TryParse(name, out string[]? components, out string? realm, out string? parseError))
            {
                ThrowTerminatingError(new ErrorRecord(
                    new ArgumentException($"Invalid principal name '{name}': {parseError}"),
                    "InvalidPrincipalName",
                    ErrorCategory.InvalidArgument,
                    name));
            }

            realm ??= _kdcs[0].Realm;
            ObolKdc? kdc = _kdcs.FirstOrDefault(k => string.Equals(k.Realm, realm, StringComparison.Ordinal));
            ObolPrincipal? principal = kdc?.Store.Find(components);
            if (principal is null)
            {
                ThrowTerminatingError(new ErrorRecord(
                    new ItemNotFoundException($"The principal '{PrincipalName.Unparse(components)}@{realm}' does " +
                        "not exist"),
                    "PrincipalNotFound",
                    ErrorCategory.ObjectNotFound,
                    name));
            }
            principals.Add(principal);
        }
        return principals;
    }
}
