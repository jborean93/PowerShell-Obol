using System;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Obol.Protocol;

namespace Obol;

/// <summary>A Kerberos KDC running in the current process.</summary>
public sealed class ObolKdc : IDisposable
{
    private readonly object _lock = new();
    private readonly KdcListener _listener;
    private readonly PrincipalStore _store;
    private Runspace? _runspace;
    private bool _disposed;
    private Exception? _error;
    private int _stopped;

    private ObolKdc(string realm, KdcListener listener, PrincipalStore store)
    {
        Realm = realm;
        _listener = listener;
        _store = store;
    }

    /// <summary>
    /// Raised for each request the KDC answered, with the request and its reply, before the reply is sent.
    /// </summary>
    /// <remarks>
    /// The event is raised on the thread that processed the request, not on a PowerShell pipeline thread, so use
    /// <c>Register-ObjectEvent</c> or <c>Trace-ObolKdc</c> to receive it in PowerShell. An exception thrown by a
    /// handler is ignored, the client still gets its reply.
    /// </remarks>
    public event EventHandler<ObolKdcEvent>? RequestProcessed;

    /// <summary>
    /// Raised for each DNS query the DC locator DNS server of a <c>DcLocator</c> SSPI environment answered for the
    /// KDC, before the reply is sent.
    /// </summary>
    /// <remarks>Raised like <see cref="RequestProcessed"/> for the queries sent to the address of the KDC.
    /// </remarks>
    public event EventHandler<ObolDnsEvent>? DnsRequestProcessed;

    /// <summary>
    /// Raised for each LDAP ping the DC locator CLDAP responder of a <c>DcLocator</c> SSPI environment answered for
    /// the KDC, before the reply is sent.
    /// </summary>
    /// <remarks>Raised like <see cref="RequestProcessed"/> for the pings sent to the address of the KDC.
    /// </remarks>
    public event EventHandler<ObolLdapEvent>? LdapRequestProcessed;

    /// <summary>Raised once when the KDC stops answering requests, by Dispose or a fault.</summary>
    internal event EventHandler? Stopped;

    /// <summary>The realm the KDC serves.</summary>
    public string Realm { get; }

    /// <summary>The endpoint the KDC listens on, the same port is used for TCP and UDP.</summary>
    public IPEndPoint Endpoint => _listener.Endpoint;

    /// <summary>The port the KDC listens on.</summary>
    public int Port => _listener.Endpoint.Port;

    /// <summary>The transports the KDC listens on.</summary>
    public ObolKdcTransport Transport => _listener.Transport;

    /// <summary>The largest UDP reply sent, larger replies are replaced by KRB_ERR_RESPONSE_TOO_BIG.</summary>
    public int MaxUdpReplySize => _listener.MaxUdpReplySize;

    /// <summary>Whether principal names are matched case insensitively.</summary>
    public bool CaseInsensitivePrincipal => _store.CaseInsensitive;

    /// <summary>The domain SID the principal SIDs in the PAC are based on.</summary>
    public string DomainSid => _store.DomainSid.ToString();

    /// <summary>The local time the KDC was started.</summary>
    public DateTime StartTime { get; private set; }

    /// <summary>Whether the KDC is running, has been stopped or stopped because of an error.</summary>
    public ObolKdcState State
    {
        get
        {
            lock (_lock)
            {
                if (_error is not null)
                {
                    return ObolKdcState.Faulted;
                }
                return _disposed ? ObolKdcState.Stopped : ObolKdcState.Running;
            }
        }
    }

    /// <summary>The error that stopped the KDC when <see cref="State"/> is Faulted.</summary>
    public Exception? Error
    {
        get
        {
            lock (_lock)
            {
                return _error;
            }
        }
    }

    /// <summary>
    /// Creates the KDC and binds the endpoint, call <see cref="Start()"/> to start answering requests.
    /// </summary>
    /// <remarks>
    /// The port is reserved once bound, requests sent before <see cref="Start()"/> wait in the TCP backlog or UDP
    /// receive buffer so principals can be added before any request is answered.
    /// </remarks>
    /// <param name="realm">The realm the KDC serves.</param>
    /// <param name="endpoint">The endpoint to bind, port 0 picks a free port.</param>
    /// <param name="transport">The transports to listen on.</param>
    /// <param name="maxUdpReplySize">The largest UDP reply to send.</param>
    /// <param name="caseInsensitivePrincipal">Whether principal names are matched case insensitively.</param>
    /// <param name="domainSid">The values after S-1-5-21- of the domain SID, random if not set.</param>
    internal static ObolKdc Bind(
        string realm,
        IPEndPoint endpoint,
        ObolKdcTransport transport,
        int maxUdpReplySize,
        bool caseInsensitivePrincipal,
        uint[]? domainSid)
    {
        PrincipalStore store = new(realm, caseInsensitivePrincipal, domainSid);
        KdcListener listener = KdcListener.Bind(store, endpoint, transport, maxUdpReplySize);
        return new(realm, listener, store);
    }

    /// <summary>Starts answering requests.</summary>
    internal void Start()
    {
        StartTime = DateTime.Now;
        _listener.Start(OnFault, OnExchange);
    }

    /// <summary>The principals of the KDC's realm.</summary>
    internal PrincipalStore Store => _store;

    /// <summary>Lists the KDC in the runspace and stops it when the runspace closes.</summary>
    internal void RegisterRunspace(Runspace runspace)
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }
            _runspace = runspace;
            runspace.StateChanged += OnRunspaceStateChanged;

            ModuleSettings.GetForRunspace(runspace).AddKdc(this);
        }
    }

    /// <summary>Stops listening, closes any open TCP connections and removes it from the runspace.</summary>
    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;

            if (_runspace is not null)
            {
                _runspace.StateChanged -= OnRunspaceStateChanged;
                ModuleSettings.GetForRunspace(_runspace).RemoveKdc(this);
                _runspace = null;
            }
        }

        _listener.Dispose();
        RaiseStopped();
    }

    public override string ToString() => $"{Realm} ({Endpoint})";

    private void OnExchange(KdcExchange exchange)
        => Raise(RequestProcessed, () => new ObolKdcEvent(this, exchange));

    /// <summary>Raises <see cref="DnsRequestProcessed"/> or <see cref="LdapRequestProcessed"/> for a request the DC
    /// locator listeners answered for the KDC.</summary>
    internal void OnLocatorExchange(DcLocatorExchange exchange)
    {
        if (exchange is DcLocatorDnsExchange dns)
        {
            Raise(DnsRequestProcessed, () => new ObolDnsEvent(this, dns));
        }
        else if (exchange is DcLocatorLdapExchange ldap)
        {
            Raise(LdapRequestProcessed, () => new ObolLdapEvent(this, ldap));
        }
    }

    /// <summary>
    /// Raises an event, each handler on its own so one failing does not skip the others. The event object is only
    /// built if there is a handler.
    /// </summary>
    private void Raise<T>(EventHandler<T>? handlers, Func<T> createEvent) where T : ObolTraceEvent
    {
        if (handlers is null)
        {
            return;
        }

        T traceEvent = createEvent();
        foreach (Delegate handler in handlers.GetInvocationList())
        {
            try
            {
                ((EventHandler<T>)handler)(this, traceEvent);
            }
            catch (Exception)
            {
                // A handler failure is not the KDC's concern, the client still gets its reply.
            }
        }
    }

    private void RaiseStopped()
    {
        if (Interlocked.Exchange(ref _stopped, 1) == 0)
        {
            Stopped?.Invoke(this, EventArgs.Empty);
        }
    }

    /// <summary>Stops the listener after a receive loop failed unexpectedly.</summary>
    /// <remarks>
    /// The KDC stays listed in the runspace so Get-ObolKdc shows it as faulted until it is stopped.
    /// </remarks>
    internal void OnFault(Exception error)
    {
        lock (_lock)
        {
            if (_disposed || _error is not null)
            {
                return;
            }
            _error = error;
        }

        // The listener waits for the failed loop to finish, run it elsewhere so the loop can return.
        _ = Task.Run(_listener.Dispose);
        RaiseStopped();
    }

    private void OnRunspaceStateChanged(object? sender, RunspaceStateEventArgs e)
    {
        if (e.RunspaceStateInfo.State is RunspaceState.Closing or RunspaceState.Closed or RunspaceState.Broken)
        {
            Dispose();
        }
    }
}
