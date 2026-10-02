# Obol
## about_Obol

# SHORT DESCRIPTION
Obol is a PowerShell module that runs a Kerberos KDC endpoint for testing.

# LONG DESCRIPTION
Obol hosts a Kerberos Key Distribution Center (KDC) inside a PowerShell process, using the [Kerberos.NET](https://github.com/dotnet/Kerberos.NET) library for the Kerberos messages and cryptography.
It is designed to provide a lightweight KDC for testing and development scenarios without needing a full Active Directory or MIT/Heimdal KDC deployment.

Obol is designed for testing and learning purposes.
It should not be considered a secure solution for production environments and must not be used as the KDC for a real realm.

The module and its dependencies are loaded in a separate AssemblyLoadContext to avoid conflicts with other assemblies loaded in the PowerShell process.

# PRINCIPAL FLAGS
Options are turned on for a principal with the `-Flag` parameter of `New-ObolPrincipal`, `New-ObolPrincipalSetting` and `Set-ObolPrincipal`, and the `Flag` property of a principal shows the options that are on.
The values are named after the AD `userAccountControl` flags but use Obol's own numbers, use the names rather than AD values.

+ `None`: No options are set.
+ `DoesNotRequirePreAuth`: The principal can get a ticket without pre-authentication.
  The KDC replies to an AS-REQ for the principal with a ticket encrypted with the principal's key without the client proving it knows the key first.
  This is the AD flag `DONT_REQ_PREAUTH` (`0x400000`), an MIT principal without the `requires_preauth` attribute and the PAC `USER_DONT_REQUIRE_PREAUTH` (`0x10000`).
+ `NotDelegated`: The principal never gets a forwardable ticket so its credentials cannot be delegated.
  A request for a forwardable ticket gets one that is not forwardable and a request to forward a ticket fails, also for a forwardable TGT issued before the flag was set.
  This is the AD flag `NOT_DELEGATED` (`0x100000`), "Account is sensitive and cannot be delegated", the MIT `-allow_forwardable` attribute and the PAC `USER_NOT_DELEGATED` (`0x4000`).
+ `TrustedForDelegation`: Tickets for the principal have the OK-AS-DELEGATE flag, telling clients they can delegate their credentials to it.
  Windows only sends a forwarded TGT to a service with this flag, MIT clients only check it with the `enforce_ok_as_delegate` setting.
  This is the AD flag `TRUSTED_FOR_DELEGATION` (`0x80000`), the MIT `+ok_as_delegate` attribute and the PAC `USER_TRUSTED_FOR_DELEGATION` (`0x2000`).

# ENCRYPTION TYPES
The keys of a principal are set with the `-EncryptionType` parameter of `New-ObolPrincipal`, `New-ObolPrincipalSetting` and `Set-ObolPrincipal`, and the `EncryptionType` property of a principal shows the types it has keys for in order of preference.
A principal gets `Aes256Sha1, Aes128Sha1` keys by default, like AD and MIT.
The supported values are:

+ `Aes128Sha1`: `aes128-cts-hmac-sha1-96` (17) from RFC 3962
+ `Aes256Sha1`: `aes256-cts-hmac-sha1-96` (18) from RFC 3962
+ `Aes128Sha256`: `aes128-cts-hmac-sha256-128` (19) from RFC 8009
+ `Aes256Sha384`: `aes256-cts-hmac-sha384-192` (20) from RFC 8009

Windows supports the RFC 8009 types from Windows 11 24H2 and Windows Server 2025 but they are disabled by default, use the RFC 3962 types for other Windows hosts.
RC4 and DES are not supported.

A key is created for each type, derived from the password of the principal or random.
The order of the types decides how the keys are used:

+ The first type is used to encrypt tickets for the principal, like the first key of an MIT principal.
  AD KDCs are slightly different, they always uses the strongest type the account allows, which is the same as the default order.
+ The session key of a ticket for the principal is the first type the client requested that the principal has a key for, like the `msDS-SupportedEncryptionTypes` of an AD account.
  A client that requests none of the types gets a `KDC_ERR_ETYPE_NOSUPP` error.

The `krbtgt/<realm>` principal is created with random keys for `Aes256Sha1, Aes128Sha1, Aes256Sha384, Aes128Sha256`, in that order.
TGTs are encrypted with the first key and the TGT session key is the first type the client requested that the krbtgt has a key for.

Use `Set-ObolPrincipal -EncryptionType` to choose the keys the krbtgt keeps and their order, such as to issue TGTs encrypted with an AES SHA-2 key or to limit the TGT session key types:

```powershell
$kdc = Start-ObolKdc -Realm EXAMPLE.TEST
$kdc | Get-ObolPrincipal krbtgt/* | Set-ObolPrincipal -EncryptionType Aes256Sha384, Aes128Sha256
```

Choosing from the existing keys keeps the key version number.
Add `-NewRandomKey` to create new keys instead, this increases the key version number and TGTs issued before the change are rejected with `KRB_AP_ERR_BADKEYVER`.
Change the encryption types before clients request TGTs so no issued TGT is affected.

# PRINCIPAL SIDS
Tickets include a PAC with the SID of the principal, the SID of the Domain Users group (RID `513`) as its primary group and the domain SID.
The SID of a principal is the domain SID of the KDC followed by the RID of the principal:

+ The domain SID is random unless it is set with `Start-ObolKdc -DomainSid`, its value is in the `DomainSid` property of the KDC.
+ The `krbtgt/<realm>` principal has the RID `502`.
+ Other principals get the next RID from `1000` that is not used, or the RID set with `New-ObolPrincipal -Rid`.
  RIDs are not reused after a principal is removed unless they are set with `-Rid`.

Set the domain SID and RIDs to get the same SIDs each time a KDC is started, such as for access control entries that refer to them, or to match the SIDs of an existing domain.

# KEYS AND SALTS
A principal's long-term keys come from one of three places:

+ A password with `-Password`: a key is derived for each encryption type from the password and a salt (RFC 3962 and RFC 8009).
+ Random keys when neither `-Password` nor `-Key` is set, like MIT `addprinc -randkey`.
+ Existing keys from a keytab with `-Key`, see [KEYS FROM A KEYTAB](#keys-from-a-keytab).

The salt is a string combined with the password so the same password gives different keys for different principals.
By default it is the RFC 4120 salt used by MIT and Heimdal, the realm followed by each name component, such as `EXAMPLE.TESTHTTPweb.example.test`.
The KDC tells a client the salt in its reply (`PA-ETYPE-INFO2`) when the client authenticates with a password, so a password login works whatever the salt is.

The salt only matters when the KDC's keys must be the same as keys derived somewhere else, where nothing asks the KDC for the salt:

+ An account of another KDC, such as an AD account whose keys a service already has from a `ktpass` or `msktutil` keytab, or a domain joined Windows host whose computer account keys are derived from its machine password.
  AD uses its own salts, use `ConvertTo-ObolSalt` to get them and set the account's `msDS-KeyVersionNumber` with `-Kvno` so the keytab matches.
+ A keytab made with `New-ObolKeytabEntry -Password` for a principal created with a different salt.

When the KDC creates the keys and a service gets them with `Export-ObolKeytab` or `ConvertTo-ObolKeytab` the salt never matters, the service has the same keys.

Random keys have no salt and no password can log in with them, they suit principals that only use their keys from a keytab, such as services, clients that log in with `kinit -k` or a keytab credential, and the `krbtgt` principal.
Use `-Password` and export the keytab for a principal that needs both password and keytab logins.

This creates a service principal with the keys of the AD account `svc_web` for the same password, so a `ktpass` keytab made for the account decrypts the tickets the KDC issues:

```powershell
$password = Read-Host -AsSecureString -Prompt Password
$kdc = Start-ObolKdc -Realm CORP.EXAMPLE
$salt = ConvertTo-ObolSalt svc_web -Realm CORP.EXAMPLE -SaltType ADUser
$kdc | New-ObolPrincipal HTTP/web.corp.example -Password $password -Salt $salt -Kvno 3
```

# KEYS FROM A KEYTAB
The `-Key` parameter of `New-ObolPrincipal`, `Set-ObolPrincipal` and `New-ObolPrincipalSetting` gives a principal the keys of keytab entries, as output by `Import-ObolKeytab`, `ConvertFrom-ObolKeytab` or `New-ObolKeytabEntry`.
Use it when a service already has a keytab, such as one built into a container image or made by `ktpass`, so the service can decrypt the tickets the KDC issues.

The keys are chosen from the entries like this:

+ Only entries for the principal's name or one of its aliases in the KDC realm are used, others are ignored, so the entries of a whole keytab can be passed.
+ An entry with an encryption type Obol does not support, such as RC4 or DES, or a key of the wrong size writes a warning and is ignored.
+ The keys with the newest kvno are used unless `-Kvno` chooses another one, the principal gets that kvno and the encryption types of those keys in the order of the entries.
+ A type that only has a key with an older kvno writes a warning, it is most likely a key that was not updated.
+ Different keys for the same encryption type and kvno, or no usable entry, is an error and the principal is not created or changed.

`-Key` cannot be used with `-Password`, `-NewRandomKey` or `-EncryptionType`, filter the entries with `Where-Object` to choose the encryption types.
A keytab does not hold the salt of its keys, set `-Salt` if a client logs in with the password the keys were derived from and the salt is not the default, see [KEYS AND SALTS](#keys-and-salts).

```powershell
$kdc | New-ObolPrincipal HTTP/web.example.test -Key (Import-ObolKeytab ./http.keytab)
```
