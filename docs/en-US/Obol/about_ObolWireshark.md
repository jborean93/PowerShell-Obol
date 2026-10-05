# ObolWireshark
## about_ObolWireshark

# SHORT DESCRIPTION
How to decrypt a Wireshark capture of the traffic to an Obol KDC and the tickets it issues.

# LONG DESCRIPTION
Wireshark decodes Kerberos messages and can decrypt their encrypted parts when it is given the keys.
As Obol holds every key of its realm, a capture of a client talking to an Obol KDC and to a service in its realm can be decrypted completely, including the tickets, the authenticators and the PAC, which neither the client nor the service can see on their own.

Wireshark takes the keys from a keytab file.
It matches the keys by encryption type and tries each one, the principal names in the keytab do not matter, so one keytab with every key of the realm decrypts everything.
Once it has decrypted a ticket it learns the session key inside it and uses that for the authenticator and the `TGS-REP` of the following requests, nothing else is needed.

# EXPORTING THE KEYS
`Export-ObolKeytab` writes the keys of principals to a keytab, there is no filtering so every principal of a KDC can be exported, including the `krbtgt` principal that encrypts the TGTs:

```powershell
$kdc | Get-ObolPrincipal | Export-ObolKeytab -Path ./obol.keytab
```

Export after the principals have been created and again after any change to their keys, such as `Set-ObolPrincipal -Password` or `-EncryptionType`, as a capture made before the change needs the old keys.
Random keys, the default for a principal created without a password and for the `krbtgt` principal, only exist in the KDC, the export is the only way to get them.

The keytab holds the secrets of the test realm, keep it with the capture it decrypts.

# WHICH KEYS A CAPTURE NEEDS
Each part of a Kerberos exchange is encrypted with a different key, and Wireshark needs the long-term key at the root of each chain:

+ `AS-REQ` to `AS-REP`: the `PA-ENC-TIMESTAMP` pre-authentication and the `enc-part` of the `AS-REP`, which holds the TGT session key, are encrypted with the client's long-term key.
  The TGT inside the `AS-REP` is encrypted with the `krbtgt` key.
+ `TGS-REQ` to `TGS-REP`: the TGT in `PA-TGS-REQ` is encrypted with the `krbtgt` key, and decrypting it gives the TGT session key that encrypts the authenticator and, with the subkey in the authenticator, the `enc-part` of the `TGS-REP`.
  The service ticket inside the `TGS-REP` is encrypted with the service's long-term key.
+ `AP-REQ` to the service: the ticket is encrypted with the service's long-term key and the authenticator with the service ticket session key it holds.

So the keytab a test gives a client or a service is not enough on its own.
A keytab exported for `user` and `HTTP/web.example.test` lets Wireshark decrypt the `AS-REP` `enc-part` and the service ticket, but not the TGT, and without the TGT it never learns the TGT session key, so the `TGS-REQ` authenticator and the `TGS-REP` `enc-part` stay encrypted.
The `krbtgt` key is only ever in the KDC, which is why the export above takes every principal.

The `Key` property of a `Trace-ObolKdc` event is exactly this set for that exchange, as keytab entries: the client's key and the `krbtgt` key for an `AS-REQ`, the `krbtgt` key and the service's key for a `TGS-REQ`.
They are the keys as they were at the time of the request, so a keytab that decrypts a trace can be written with `Export-ObolKeytab -Entry` whatever the keys of the principals are now:

```powershell
$events = Use-ObolKrb5Environment EXAMPLE.TEST -Principal @{ user = $null } -ClientPrincipal user {
    param ($kdc)

    Trace-ObolKdc -Kdc $kdc { kinit -k -i user }
}
$keys = $events.Key | Sort-Object FullName, Kvno, EncryptionType -Unique
Export-ObolKeytab -Entry $keys -Path ./trace.keytab
```

# WIRESHARK SETTINGS
Open `Edit > Preferences > Protocols > KRB5` and:

+ Set `Kerberos keytab file` to the exported keytab.
+ Turn on `Try to decrypt Kerberos blobs`.

Wireshark then shows the decrypted `enc-part` of each ticket and reply under the encrypted field, with the session key, the ticket flags, the times and the authorization data including the PAC.
The decryption needs a Wireshark built with Kerberos support, which the Windows installers, the macOS installer and most Linux packages are.
`Help > About Wireshark` lists `Kerberos` under the compiled features when it is.

Wireshark decodes Kerberos on port 88.
A KDC started without `-Port 88` uses a random port, right-click a packet to it and use `Decode As` with `KRB5` for that port, or start the KDC with `-Port 88`.

# CAPTURING LOOPBACK TRAFFIC
An Obol KDC usually listens on a loopback address and the clients run on the same host.
On Linux and macOS capture on the loopback interface, `lo` or `lo0`.
On Windows capture on the `Adapter for loopback traffic capture` that Npcap installs when the `Support loopback traffic` option is selected.

# SEE ALSO
+ [Trace-ObolKdc](./Trace-ObolKdc.md)
+ [Export-ObolKeytab](./Export-ObolKeytab.md)
+ [about_Obol](./about_Obol.md)
