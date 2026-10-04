using System;
using System.Management.Automation;
using System.Runtime.Versioning;

namespace Obol.Commands;

[Cmdlet(
    VerbsCommon.Add, "ObolSspiKdc",
    SupportsShouldProcess = true
)]
[OutputType(typeof(ObolSspiKdc))]
public sealed class AddObolSspiKdc : PSCmdlet
{
    [Parameter(Mandatory = true, Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Realm { get; set; } = "";

    [Parameter(Mandatory = true, Position = 1)]
    [ValidateNotNullOrEmpty]
    public string KdcAddress { get; set; } = "";

    [Parameter]
    [ValidateSet("Thread", "Machine")]
    public ObolSspiKdcScope Scope { get; set; } = ObolSspiKdcScope.Thread;

    [Parameter]
    public ObolSspiDcFlags DcFlags { get; set; } = ObolSspiDcFlags.None;

    [Parameter]
    public SwitchParameter PassThru { get; set; }

    protected override void EndProcessing()
    {
        if (!OperatingSystem.IsWindows())
        {
            ThrowTerminatingError(SspiCommandHelper.NotWindowsError("Add-ObolSspiKdc"));
            return;
        }

        if (SspiCommandHelper.CheckKdcAddress(KdcAddress) is ErrorRecord addressError)
        {
            ThrowTerminatingError(addressError);
            return;
        }

        bool machine = Scope == ObolSspiKdcScope.Machine;
        string action = machine ? "Add machine KDC binding" : "Pin KDC for the current thread";
        if (!ShouldProcess($"{Realm} -> {KdcAddress}", action))
        {
            return;
        }

        ObolSspiKdc? result;
        try
        {
            result = machine
                ? AddMachine(Realm, KdcAddress, DcFlags, PassThru)
                : Pin(Realm, KdcAddress, DcFlags);
        }
        catch (SspiKdcException e)
        {
            ThrowTerminatingError(SspiCommandHelper.SspiError(e));
            return;
        }

        if (PassThru && result is not null)
        {
            WriteObject(result);
        }
    }

    /// <summary>Pins the realm to the KDC for the current thread and records it.</summary>
    [SupportedOSPlatform("windows")]
    private static ObolSspiKdc Pin(string realm, string kdcAddress, ObolSspiDcFlags flags)
    {
        SspiKdc.PinKdc(realm, kdcAddress, (int)flags);
        return SspiPinRegistry.Add(ObolSspiKdc.ForThread(realm, kdcAddress, flags));
    }

    /// <summary>Adds a machine binding, impersonating SYSTEM, and re-reads it for -PassThru.</summary>
    [SupportedOSPlatform("windows")]
    private static ObolSspiKdc? AddMachine(string realm, string kdcAddress, ObolSspiDcFlags dcFlags, bool passThru)
    {
        ObolSspiKdcAddressType addressType = SspiCommandHelper.InferAddressType(kdcAddress);
        using (SystemImpersonation.Acquire())
        {
            SspiKdc.AddBinding(realm, kdcAddress, (int)addressType, (int)dcFlags);
            if (!passThru)
            {
                return null;
            }

            foreach (ObolSspiKdc binding in SspiKdc.QueryBindings())
            {
                if (string.Equals(binding.Realm, realm, StringComparison.OrdinalIgnoreCase))
                {
                    return binding;
                }
            }

            // The entry was not read back, return one built from the inputs so -PassThru still produces an object.
            return ObolSspiKdc.ForMachine(
                realm, kdcAddress, dcFlags, DateTime.Now, "", addressType, ObolSspiDcLocatorFlags.None,
                ObolSspiKdcCacheFlags.None);
        }
    }
}
