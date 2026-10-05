# ObolKdcEvent
## about_ObolKdcEvent

# SHORT DESCRIPTION
The object `Trace-ObolKdc` and the `RequestProcessed` event give for each request a KDC answers, and the Kerberos messages inside it.

# LONG DESCRIPTION
Every request an Obol KDC answers is reported as an `ObolKdcEvent`.
The event holds the facts of the exchange and the two messages, the request as received and the reply as sent, decoded into objects under the `Obol.Kerberos` namespace.
The parts of the messages the KDC decrypted or built are decrypted in the objects, so the ticket, the authenticator and the PAC can be inspected, which neither the client nor the service can do on their own.

# WARNING
The structure of the event and of the message objects is for viewing and diagnostics, it is not a public API to build a workflow or a test suite on.
Properties may be added, renamed, moved or removed in any release when a better representation is found.
Changes are documented in the CHANGELOG.
Assert on the stable properties of the event, `ClientName`, `ServiceName`, `ErrorCode`, `Message` and `Key`, and treat the rest as something to look at.

# THE EVENT
The properties of the event itself:

+ `Message`: A one line summary, the default output shows it with `Time` and the client. See [THE MESSAGE SUMMARY](#the-message-summary).
+ `Kdc` and `Realm`: The KDC that answered the request and its realm.
+ `Time` and `Duration`: The local time the request was received and how long the KDC took to process it.
+ `Transport` and `ClientAddress`: `Tcp` or `Udp`, and the IP address and port the client sent the request from.
+ `ClientName` and `ServiceName`: The client and service principals with their realm, such as `user@EXAMPLE.TEST` and `krbtgt/EXAMPLE.TEST@EXAMPLE.TEST`, as the client sent them. The client of a TGS-REQ comes from the TGT. `$null` when the request was not decoded that far.
+ `ErrorCode`: `None` when a ticket was issued, otherwise the `error-code` of the KRB-ERROR sent such as `PreAuthRequired` or `ClientPrincipalUnknown`. The names and the RFC 4120 numbers they stand for are in `[Obol.Kerberos.ErrorCode]`.
+ `Exception`: The unexpected exception the KDC answered with a `Generic` error, such as a request that is not valid DER, otherwise `$null`.
+ `Key`: The long-term keys the request used, as keytab entries, see [THE KEYS](#the-keys).
+ `Request`: The request, see [THE REQUEST](#the-request).
+ `Reply`: The reply, see [THE REPLY](#the-reply).

A request always gets exactly one reply.
A request that cannot be decoded gets a KRB-ERROR, a reply too big for UDP is replaced by a `ResponseTooBig` error and a TCP request too long to read gets `FieldTooLong`, so every event has both messages.

# THE MESSAGES
Every message object derives from `Obol.Kerberos.Message` and has:

+ `MessageType`: `AsReq`, `AsRep`, `TgsReq`, `TgsRep`, `ApReq` or `Error`, the `msg-type` numbers of RFC 4120, or `Unknown`.
+ `Bytes`: The DER encoding as sent, without the TCP length prefix.

A message that could not be decoded is a plain `Message` with the type its outer tag claimed and the bytes.
The field names follow RFC 4120 with the Kerberos abbreviations spelt out, `cname` is `ClientName`, `sname` is `ServiceName`, `etype` is `EncryptionType`, `kvno` is `KeyVersion`.
Times are local `DateTime` values. Encryption and checksum types are the `Obol.Kerberos.EncryptionType` and `ChecksumType` enumerations whose values are the IANA numbers, so a type Obol does not support, such as `Rc4Hmac`, is still visible and one without a name is shown as its number, and the flag enumerations use the numbers Windows and MIT show.

An encrypted field appears twice, as `Encrypted<Name>` or `EncryptedPart` with the `EncryptedData` as sent, its encryption type, key version and ciphertext, and as `<Name>` or `DecryptedPart` with the decrypted object when the KDC decrypted it, otherwise `$null`.
The KDC decrypts a TGT and an authenticator before it checks them, so a TGS-REQ it rejected for an expired TGT still shows the TGT contents.

# THE REQUEST
`Request` is an `Obol.Kerberos.KdcRequest` for an AS-REQ and the derived `TgsRequest` for a TGS-REQ, the KDC-REQ of RFC 4120 5.4.1:

+ `ProtocolVersion`: The `pvno`, 5.
+ `PreAuthData`: The `padata` elements in the order sent, each a `PreAuthData` with `Type` and the `Value` bytes. The known types are derived classes with the decoded value: `TimestampPreAuthData` (PA-ENC-TIMESTAMP, with `EncryptedData` and the decrypted `Timestamp`), `TgsRequestPreAuthData` (PA-TGS-REQ, with `ApRequest`), `ETypeInfo2PreAuthData` (PA-ETYPE-INFO2, with `Entry`) and `PacRequestPreAuthData` (PA-PAC-REQUEST, with `IncludePac`).
+ `Body`: The `req-body`, a `KdcRequestBody` with `KdcOption`, `ClientName`, `Realm`, `ServiceName`, `From`, `Till`, `RenewTill`, `Nonce`, `EncryptionType`, `Address`, `EncryptedAuthorizationData` and `AdditionalTicket`.
+ `ApRequest`: On a `TgsRequest`, the AP-REQ of the PA-TGS-REQ, see below. `$null` if the request had none.

The `ApRequest` is an `Obol.Kerberos.ApRequest`, the AP-REQ of RFC 4120 5.5.1:

+ `ApOption`: The `ap-options`.
+ `Ticket`: The TGT presented, see [TICKETS](#tickets).
+ `EncryptedAuthenticator` and `Authenticator`: The authenticator as sent and decrypted. The `Authenticator` has `ClientName`, `Checksum` (of the request body, `RsaMd5` is what Windows sends), `Time`, `Subkey`, `SequenceNumber` and `AuthorizationData`.

# THE REPLY
`Reply` is an `Obol.Kerberos.KdcReply` when a ticket was issued, the KDC-REP of RFC 4120 5.4.2:

+ `ProtocolVersion` and `PreAuthData`: An AS-REP carries `ETypeInfo2PreAuthData` with the salt of the client's key.
+ `ClientName`: The client the ticket was issued to.
+ `Ticket`: The ticket, see [TICKETS](#tickets).
+ `EncryptedPart` and `DecryptedPart`: The part only the client can read, encrypted with the client's key for an AS-REP and the subkey or TGT session key for a TGS-REP. The `KdcReplyPart` has `Key` (the session key), `LastRequest`, `Nonce`, `KeyExpiration`, `Flag`, `AuthTime`, `StartTime`, `EndTime`, `RenewTill`, `ServiceName`, `Address` and `EncryptedPreAuthData` (PA-SUPPORTED-ENCTYPES).

`Reply` is an `Obol.Kerberos.ErrorReply` otherwise, the KRB-ERROR of RFC 4120 5.9.1:

+ `ErrorCode` and `ErrorText`: The `error-code` and the `e-text` with the reason, if the KDC sent one.
+ `ClientTime` and `ServerTime`: The client's time from the request, if any, and the KDC's time.
+ `ClientName` and `ServiceName`: The names, the service is the krbtgt of the realm when the request named none.
+ `ErrorData` and `MethodData`: The `e-data` bytes and, when they are METHOD-DATA such as for `PreAuthRequired`, the `PreAuthData` elements the KDC accepts, `ETypeInfo2PreAuthData` says which keys and salts.

# TICKETS
A ticket is an `Obol.Kerberos.Ticket`, RFC 4120 5.3:

+ `Version`, `Realm` and `ServiceName`: The `tkt-vno`, the issuing realm and the service the ticket is for.
+ `EncryptedPart`: As sent, encrypted with the service's long-term key, its `KeyVersion` is the kvno of that key.
+ `DecryptedPart`: A `TicketPart` with `Flag`, `Key` (the session key), `ClientName`, `TransitedType` and `Transited`, `AuthTime`, `StartTime`, `EndTime`, `RenewTill`, `Address`, `AuthorizationData` and `Pac`.

`AuthorizationData` lists the `AuthorizationData` elements with `Type` and the `Data` bytes.
AD-IF-RELEVANT is an `IfRelevantAuthorizationData` with the `Element` list inside and AD-WIN2K-PAC a `PacAuthorizationData` with the `Pac`.
`Pac` is the PAC found anywhere in the authorization data, `$null` if the ticket has none, such as a ticket for a service with the `NoAuthDataRequired` flag.

# THE PAC
The PAC is an `Obol.Kerberos.Pac`, MS-PAC:

+ `Version` and `Buffer`: The PACTYPE version and every buffer with its `Type` and raw `Data`, including the signatures.
+ `LogonInfo`: The KERB_VALIDATION_INFO buffer, a `PacLogonInfo` with the user and domain names, `DomainSid`, `UserId`, `PrimaryGroupId`, `GroupId`, `ExtraSid`, `UserAccountControl` (the MS-SAMR `USER_*` values, with `DontRequirePreAuth`, `NotDelegated`, `TrustedForDelegation` and `NoAuthDataRequired` matching the Obol principal flags), `UserFlag`, the logon and password times, and the `UserSid` and `PrimaryGroupSid` built from them.
+ `ClientInfo`: The PAC_CLIENT_INFO buffer with the client `Name` and `ClientId`, the authentication time.
+ `UpnDnsInfo`: The UPN_DNS_INFO buffer with `Upn`, `DnsDomainName` and `Flag`, `$null` for a ticket from Obol which does not write it.

# THE KEYS
`Key` holds the long-term keys the exchange used, as `ObolKeytabEntry` objects: the client's key an AS-REP is encrypted with, the krbtgt key of the TGT in a TGS-REQ and the service key the ticket is encrypted with.
The other keys of an exchange, the TGT session key and the authenticator subkey, are inside the parts these decrypt, and are also in the decrypted objects.
The keys are kept with the event so the messages can be decrypted after `Set-ObolPrincipal` changed a principal's keys, and can be written to a keytab with `Export-ObolKeytab -Entry` or `ConvertTo-ObolKeytab -Entry`, see [about_ObolWireshark](./about_ObolWireshark.md).
They are the secrets of the test realm, treat the events as such.

# THE MESSAGE SUMMARY
`Message`, also returned by `ToString()`, reads `<request type> <client> -> <service>: <outcome>`.
The outcome of a ticket is the reply type, the encryption types of the ticket and its session key, the ticket flags and `no PAC` when the ticket has none.
The outcome of an error is the error code and its text, if any.
A name is left out when the request did not get that far.

```
AS-REQ user@EXAMPLE.TEST -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: PreAuthRequired
AS-REQ user@EXAMPLE.TEST -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: AS-REP, Aes256Sha1 ticket and session key, PreAuthenticated, Initial, Renewable
TGS-REQ user@EXAMPLE.TEST -> HTTP/web.example.test@EXAMPLE.TEST: TGS-REP, Aes256Sha1 ticket and session key, PreAuthenticated, Renewable
TGS-REQ -> HTTP/web.example.test@EXAMPLE.TEST: BadIntegrity: Failed to decrypt the ticket or authenticator
Unknown request: Generic: Failed to process request: the message type Boolean is not supported
```

# SEE ALSO
+ [Trace-ObolKdc](./Trace-ObolKdc.md)
+ [about_Obol](./about_Obol.md)
+ [about_ObolWireshark](./about_ObolWireshark.md)
