using module ../output/Obol
using namespace System.IO
using namespace System.Net
using namespace System.Net.Security
using namespace System.Security.Principal

BeforeAll {
    . ([Path]::Combine($PSScriptRoot, 'common.ps1'))

    # Drives the Windows Kerberos SSP directly so the service side can use a keytab. The initiator uses a password
    # and the acceptor a keytab.
    if (-not ('ObolTests.Sspi' -as [type])) {
        Add-Type -TypeDefinition @'
#nullable enable
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ObolTests;

public sealed class SspiResult
{
    public string ClientName { get; set; } = "";
    public string ServerName { get; set; } = "";
    public int EncryptionType { get; set; }
    public bool MutualAuth { get; set; }
    public bool WrapRoundTrip { get; set; }
}

public sealed class SspiAcceptResult
{
    public byte[] Token { get; set; } = Array.Empty<byte>();
    public bool Completed { get; set; }
    public string ClientName { get; set; } = "";
}

public static class Sspi
{
    private const int SECPKG_CRED_INBOUND = 1;
    private const int SECPKG_CRED_OUTBOUND = 2;
    private const int SECBUFFER_DATA = 1;
    private const int SECBUFFER_TOKEN = 2;
    private const int SECBUFFER_PADDING = 9;
    private const int SEC_E_OK = 0;
    private const int SEC_I_CONTINUE_NEEDED = 0x00090312;
    private const int ISC_REQ_MUTUAL_AUTH = 0x2;
    private const int ISC_REQ_CONFIDENTIALITY = 0x10;
    private const int ISC_REQ_ALLOCATE_MEMORY = 0x100;
    private const int ISC_REQ_INTEGRITY = 0x10000;
    private const int ISC_RET_MUTUAL_AUTH = 0x2;
    private const int ASC_REQ_MUTUAL_AUTH = 0x2;
    private const int ASC_REQ_CONFIDENTIALITY = 0x10;
    private const int ASC_REQ_ALLOCATE_MEMORY = 0x100;
    private const int ASC_REQ_INTEGRITY = 0x20000;
    private const int SECPKG_ATTR_SIZES = 0;
    private const int SECPKG_ATTR_NAMES = 1;
    private const int SECPKG_ATTR_KEY_INFO = 5;
    private const int SECPKG_ATTR_NATIVE_NAMES = 13;
    private static readonly Guid SEC_WINNT_AUTH_DATA_TYPE_KEYTAB = new("D587AAE8-F78F-4455-A112-C934BEEE7CE1");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SEC_WINNT_AUTH_IDENTITY_W
    {
        public string User;
        public int UserLength;
        public string? Domain;
        public int DomainLength;
        public string Password;
        public int PasswordLength;
        public int Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SEC_WINNT_AUTH_IDENTITY_EX2
    {
        public int Version;
        public short cbHeaderLength;
        public int cbStructureLength;
        public int UserOffset;
        public short UserLength;
        public int DomainOffset;
        public short DomainLength;
        public int PackedCredentialsOffset;
        public short PackedCredentialsLength;
        public int Flags;
        public int PackageListOffset;
        public short PackageListLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SEC_WINNT_AUTH_PACKED_CREDENTIALS
    {
        public short cbHeaderLength;
        public short cbStructureLength;
        public Guid CredType;
        public int ByteArrayOffset;
        public short ByteArrayLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecBuffer
    {
        public int cbBuffer;
        public int BufferType;
        public IntPtr pvBuffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecBufferDesc
    {
        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffers;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecPkgContext_Sizes
    {
        public int cbMaxToken;
        public int cbMaxSignature;
        public int cbBlockSize;
        public int cbSecurityTrailer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecPkgContext_KeyInfoW
    {
        public IntPtr sSignatureAlgorithmName;
        public IntPtr sEncryptAlgorithmName;
        public int KeySize;
        public int SignatureAlgorithm;
        public int EncryptAlgorithm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecPkgContext_NativeNamesW
    {
        public IntPtr sClientName;
        public IntPtr sServerName;
    }

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    private static extern int AcquireCredentialsHandleW(string? principal, string package, int credentialUse,
        IntPtr logonId, IntPtr authData, IntPtr getKeyFn, IntPtr getKeyArgument, IntPtr credential, out long expiry);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    private static extern int InitializeSecurityContextW(IntPtr credential, IntPtr context, string target,
        int contextReq, int reserved1, int targetDataRep, IntPtr input, int reserved2, IntPtr newContext,
        IntPtr output, out int contextAttr, out long expiry);

    [DllImport("secur32.dll")]
    private static extern int AcceptSecurityContext(IntPtr credential, IntPtr context, IntPtr input, int contextReq,
        int targetDataRep, IntPtr newContext, IntPtr output, out int contextAttr, out long expiry);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    private static extern int QueryContextAttributesW(IntPtr context, int attribute, IntPtr buffer);

    [DllImport("secur32.dll")]
    private static extern int EncryptMessage(IntPtr context, int qop, IntPtr message, int sequence);

    [DllImport("secur32.dll")]
    private static extern int DecryptMessage(IntPtr context, IntPtr message, int sequence, out int qop);

    [DllImport("secur32.dll")]
    private static extern int FreeContextBuffer(IntPtr buffer);

    [DllImport("secur32.dll")]
    private static extern int FreeCredentialsHandle(IntPtr credential);

    [DllImport("secur32.dll")]
    private static extern int DeleteSecurityContext(IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(IntPtr token, int access, IntPtr attributes, int level, int type,
        out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValueW(string? system, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES state,
        int length, IntPtr previous, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }

    /// <summary>
    /// Gets an impersonation token for SYSTEM with SeTcbPrivilege enabled, the caller must be an administrator.
    /// </summary>
    /// <remarks>
    /// Without SeTcbPrivilege, or running as a service, the acceptor sends the PAC to a domain controller to check
    /// its KDC signature, which fails with STATUS_TRUSTED_DOMAIN_FAILURE on a host not joined to the realm.
    /// </remarks>
    public static SafeAccessTokenHandle GetSystemToken()
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x28, out IntPtr self))
        {
            throw new Win32Exception();
        }
        try
        {
            EnablePrivilege(self, "SeDebugPrivilege");
        }
        finally
        {
            CloseHandle(self);
        }

        using Process winlogon = Process.GetProcessesByName("winlogon")[0];
        if (!OpenProcessToken(winlogon.Handle, 0x2 | 0x8, out IntPtr system))
        {
            throw new Win32Exception();
        }
        try
        {
            // TOKEN_ALL_ACCESS, SecurityImpersonation, TokenImpersonation
            if (!DuplicateTokenEx(system, 0xF01FF, IntPtr.Zero, 2, 2, out IntPtr duplicate))
            {
                throw new Win32Exception();
            }
            SafeAccessTokenHandle token = new(duplicate);
            EnablePrivilege(duplicate, "SeTcbPrivilege");
            return token;
        }
        finally
        {
            CloseHandle(system);
        }
    }

    private static void EnablePrivilege(IntPtr token, string name)
    {
        if (!LookupPrivilegeValueW(null, name, out long luid))
        {
            throw new Win32Exception();
        }
        TOKEN_PRIVILEGES privileges = new() { PrivilegeCount = 1, Luid = luid, Attributes = 2 };
        if (!AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero)
            || Marshal.GetLastWin32Error() != 0)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Failed to enable {name}");
        }
    }

    /// <summary>Gets the first Kerberos token for the target with a password, no acceptor is involved.</summary>
    public static byte[] GetToken(string user, string password, string target)
    {
        IntPtr credential = AcquirePasswordCredential(user, password);
        IntPtr context = AllocHandle();
        try
        {
            return Initialize(credential, context, first: true, target, null, out _).Token;
        }
        finally
        {
            Release(credential, context, contextCreated: true);
        }
    }

    /// <summary>
    /// Authenticates the user with a password to the service accepting with a keytab, then wraps a message both ways.
    /// </summary>
    /// <param name="acceptorToken">
    /// The token the acceptor impersonates, such as from <see cref="GetSystemToken"/>, the process token if null.
    /// </param>
    public static SspiResult Authenticate(string user, string password, string target, string servicePrincipal,
        byte[] keytab, SafeAccessTokenHandle? acceptorToken)
    {
        IntPtr initiatorCredential = AcquirePasswordCredential(user, password);
        IntPtr acceptorCredential = IntPtr.Zero;
        IntPtr initiatorContext = AllocHandle();
        IntPtr acceptorContext = AllocHandle();
        bool initiatorCreated = false;
        bool acceptorCreated = false;
        try
        {
            acceptorCredential = AsAcceptor(acceptorToken, () => AcquireKeytabCredential(servicePrincipal, keytab));

            byte[]? input = null;
            bool initiatorDone = false;
            bool acceptorDone = false;
            int initiatorAttributes = 0;
            for (int i = 0; i < 4 && !(initiatorDone && acceptorDone); i++)
            {
                if (!initiatorDone)
                {
                    (byte[] token, bool done) = Initialize(initiatorCredential, initiatorContext, !initiatorCreated,
                        target, input, out initiatorAttributes);
                    initiatorCreated = true;
                    initiatorDone = done;
                    input = token;
                    if (token.Length == 0)
                    {
                        continue;
                    }
                }
                if (!acceptorDone)
                {
                    bool first = !acceptorCreated;
                    (byte[] token, bool done) = AsAcceptor(acceptorToken,
                        () => Accept(acceptorCredential, acceptorContext, first, input!));
                    acceptorCreated = true;
                    acceptorDone = done;
                    input = token;
                }
            }
            if (!(initiatorDone && acceptorDone))
            {
                throw new InvalidOperationException("The security contexts did not complete");
            }

            SspiResult result = new()
            {
                ClientName = QueryString(acceptorContext, SECPKG_ATTR_NAMES),
                MutualAuth = (initiatorAttributes & ISC_RET_MUTUAL_AUTH) != 0,
            };
            (result.ServerName, _) = QueryNativeNames(initiatorContext);
            result.EncryptionType = QueryEncryptionType(initiatorContext);

            // A message encrypted by each side decrypts on the other.
            string sent = Guid.NewGuid().ToString();
            string received = Unwrap(acceptorContext, Wrap(initiatorContext, Encoding.UTF8.GetBytes(sent)));
            string reply = Unwrap(initiatorContext, Wrap(acceptorContext, Encoding.UTF8.GetBytes(received)));
            result.WrapRoundTrip = reply == sent;
            return result;
        }
        finally
        {
            Release(initiatorCredential, initiatorContext, initiatorCreated);
            Release(acceptorCredential, acceptorContext, acceptorCreated);
        }
    }

    /// <summary>
    /// Accepts the first token of another initiator for the service with a keytab, returning the AP-REP to send back.
    /// </summary>
    /// <param name="acceptorToken">
    /// The token the acceptor impersonates, such as from <see cref="GetSystemToken"/>, the process token if null.
    /// </param>
    public static SspiAcceptResult AcceptToken(byte[] token, string servicePrincipal, byte[] keytab,
        SafeAccessTokenHandle? acceptorToken)
    {
        IntPtr credential = IntPtr.Zero;
        IntPtr context = AllocHandle();
        bool created = false;
        try
        {
            credential = AsAcceptor(acceptorToken, () => AcquireKeytabCredential(servicePrincipal, keytab));
            (byte[] reply, bool done) = AsAcceptor(acceptorToken, () => Accept(credential, context, true, token));
            created = true;
            return new SspiAcceptResult
            {
                Token = reply,
                Completed = done,
                ClientName = done ? QueryString(context, SECPKG_ATTR_NAMES) : "",
            };
        }
        finally
        {
            Release(credential, context, created);
        }
    }

    private static T AsAcceptor<T>(SafeAccessTokenHandle? token, Func<T> func)
        => token is null ? func() : WindowsIdentity.RunImpersonated(token, func);

    private static IntPtr AllocHandle()
    {
        IntPtr handle = Marshal.AllocHGlobal(IntPtr.Size * 2);
        Marshal.WriteIntPtr(handle, IntPtr.Zero);
        Marshal.WriteIntPtr(handle, IntPtr.Size, IntPtr.Zero);
        return handle;
    }

    private static void Release(IntPtr credential, IntPtr context, bool contextCreated)
    {
        if (contextCreated)
        {
            DeleteSecurityContext(context);
        }
        Marshal.FreeHGlobal(context);
        if (credential != IntPtr.Zero)
        {
            FreeCredentialsHandle(credential);
            Marshal.FreeHGlobal(credential);
        }
    }

    private static void Check(int status, string function)
    {
        if (status != SEC_E_OK)
        {
            throw new Win32Exception(status, $"{function} failed 0x{status:X8}: {new Win32Exception(status).Message}");
        }
    }

    private static IntPtr AcquirePasswordCredential(string user, string password)
    {
        SEC_WINNT_AUTH_IDENTITY_W identity = new()
        {
            User = user,
            UserLength = user.Length,
            Password = password,
            PasswordLength = password.Length,
            Flags = 2, // SEC_WINNT_AUTH_IDENTITY_UNICODE
        };
        IntPtr authData = Marshal.AllocHGlobal(Marshal.SizeOf<SEC_WINNT_AUTH_IDENTITY_W>());
        IntPtr credential = AllocHandle();
        try
        {
            Marshal.StructureToPtr(identity, authData, false);
            Check(AcquireCredentialsHandleW(null, "Kerberos", SECPKG_CRED_OUTBOUND, IntPtr.Zero, authData,
                IntPtr.Zero, IntPtr.Zero, credential, out _), "AcquireCredentialsHandle");
            return credential;
        }
        catch
        {
            Marshal.FreeHGlobal(credential);
            throw;
        }
        finally
        {
            Marshal.DestroyStructure<SEC_WINNT_AUTH_IDENTITY_W>(authData);
            Marshal.FreeHGlobal(authData);
        }
    }

    private static IntPtr AcquireKeytabCredential(string principal, byte[] keytab)
    {
        int identityLength = Marshal.SizeOf<SEC_WINNT_AUTH_IDENTITY_EX2>();
        int packedLength = Marshal.SizeOf<SEC_WINNT_AUTH_PACKED_CREDENTIALS>();
        byte[] user = Encoding.Unicode.GetBytes(principal);
        int length = identityLength + packedLength + keytab.Length + user.Length;

        SEC_WINNT_AUTH_IDENTITY_EX2 identity = new()
        {
            Version = 0x201, // SEC_WINNT_AUTH_IDENTITY_VERSION_2
            cbHeaderLength = (short)identityLength,
            cbStructureLength = length,
            UserOffset = identityLength + packedLength + keytab.Length,
            UserLength = (short)user.Length,
            PackedCredentialsOffset = identityLength,
            PackedCredentialsLength = (short)(packedLength + keytab.Length),
            Flags = 2, // SEC_WINNT_AUTH_IDENTITY_UNICODE
        };
        SEC_WINNT_AUTH_PACKED_CREDENTIALS packed = new()
        {
            cbHeaderLength = (short)packedLength,
            cbStructureLength = (short)(packedLength + keytab.Length),
            CredType = SEC_WINNT_AUTH_DATA_TYPE_KEYTAB,
            ByteArrayOffset = packedLength,
            ByteArrayLength = (short)keytab.Length,
        };

        IntPtr authData = Marshal.AllocHGlobal(length);
        IntPtr credential = AllocHandle();
        try
        {
            Marshal.Copy(new byte[length], 0, authData, length);
            Marshal.StructureToPtr(identity, authData, false);
            Marshal.StructureToPtr(packed, authData + identityLength, false);
            Marshal.Copy(keytab, 0, authData + identityLength + packedLength, keytab.Length);
            Marshal.Copy(user, 0, authData + identity.UserOffset, user.Length);

            Check(AcquireCredentialsHandleW(null, "Kerberos", SECPKG_CRED_INBOUND, IntPtr.Zero, authData,
                IntPtr.Zero, IntPtr.Zero, credential, out _), "AcquireCredentialsHandle with a keytab");
            return credential;
        }
        catch
        {
            Marshal.FreeHGlobal(credential);
            throw;
        }
        finally
        {
            Marshal.FreeHGlobal(authData);
        }
    }

    private static (byte[] Token, bool Done) Initialize(IntPtr credential, IntPtr context, bool first, string target,
        byte[]? input, out int attributes)
    {
        using Buffers inputBuffers = input is null ? new Buffers() : new Buffers((SECBUFFER_TOKEN, input));
        using Buffers output = new((SECBUFFER_TOKEN, null));
        int status = InitializeSecurityContextW(credential, first ? IntPtr.Zero : context, target,
            ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY | ISC_REQ_CONFIDENTIALITY, 0, 0,
            input is null ? IntPtr.Zero : inputBuffers.Descriptor, 0, context, output.Descriptor,
            out attributes, out _);
        if (status != SEC_I_CONTINUE_NEEDED)
        {
            Check(status, "InitializeSecurityContext");
        }
        return (output.ReadAllocated(0), status == SEC_E_OK);
    }

    private static (byte[] Token, bool Done) Accept(IntPtr credential, IntPtr context, bool first, byte[] input)
    {
        using Buffers inputBuffers = new((SECBUFFER_TOKEN, input));
        using Buffers output = new((SECBUFFER_TOKEN, null));
        int status = AcceptSecurityContext(credential, first ? IntPtr.Zero : context, inputBuffers.Descriptor,
            ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_MUTUAL_AUTH | ASC_REQ_INTEGRITY | ASC_REQ_CONFIDENTIALITY, 0, context,
            output.Descriptor, out _, out _);
        if (status != SEC_I_CONTINUE_NEEDED)
        {
            Check(status, "AcceptSecurityContext");
        }
        return (output.ReadAllocated(0), status == SEC_E_OK);
    }

    private static T Query<T>(IntPtr context, int attribute) where T : struct
    {
        IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        try
        {
            Check(QueryContextAttributesW(context, attribute, buffer), "QueryContextAttributes");
            return Marshal.PtrToStructure<T>(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string TakeString(IntPtr value)
    {
        string result = Marshal.PtrToStringUni(value) ?? "";
        FreeContextBuffer(value);
        return result;
    }

    private static string QueryString(IntPtr context, int attribute)
        => TakeString(Query<IntPtr>(context, attribute));

    private static (string Server, string Client) QueryNativeNames(IntPtr context)
    {
        SecPkgContext_NativeNamesW names = Query<SecPkgContext_NativeNamesW>(context, SECPKG_ATTR_NATIVE_NAMES);
        string client = TakeString(names.sClientName);
        return (TakeString(names.sServerName), client);
    }

    private static int QueryEncryptionType(IntPtr context)
    {
        SecPkgContext_KeyInfoW info = Query<SecPkgContext_KeyInfoW>(context, SECPKG_ATTR_KEY_INFO);
        TakeString(info.sSignatureAlgorithmName);
        TakeString(info.sEncryptAlgorithmName);
        return info.EncryptAlgorithm;
    }

    private static byte[] Wrap(IntPtr context, byte[] data)
    {
        SecPkgContext_Sizes sizes = Query<SecPkgContext_Sizes>(context, SECPKG_ATTR_SIZES);
        using Buffers buffers = new(
            (SECBUFFER_TOKEN, new byte[sizes.cbSecurityTrailer]),
            (SECBUFFER_DATA, data),
            (SECBUFFER_PADDING, new byte[sizes.cbBlockSize]));
        Check(EncryptMessage(context, 0, buffers.Descriptor, 0), "EncryptMessage");

        byte[] token = buffers.Read(0);
        byte[] encrypted = buffers.Read(1);
        byte[] padding = buffers.Read(2);
        byte[] result = new byte[4 + token.Length + encrypted.Length + padding.Length];
        BitConverter.GetBytes(token.Length).CopyTo(result, 0);
        token.CopyTo(result, 4);
        encrypted.CopyTo(result, 4 + token.Length);
        padding.CopyTo(result, 4 + token.Length + encrypted.Length);
        return result;
    }

    private static string Unwrap(IntPtr context, byte[] wrapped)
    {
        int tokenLength = BitConverter.ToInt32(wrapped, 0);
        using Buffers buffers = new(
            (SECBUFFER_TOKEN, wrapped.AsSpan(4, tokenLength).ToArray()),
            (SECBUFFER_DATA, wrapped.AsSpan(4 + tokenLength).ToArray()));
        Check(DecryptMessage(context, buffers.Descriptor, 0, out _), "DecryptMessage");
        return Encoding.UTF8.GetString(buffers.Read(1));
    }

    /// <summary>A SecBufferDesc and its buffers in unmanaged memory, a null buffer is allocated by SSPI.</summary>
    private sealed class Buffers : IDisposable
    {
        private readonly IntPtr _buffers;
        private readonly IntPtr[] _owned;
        private readonly int _count;

        public Buffers(params (int Type, byte[]? Data)[] buffers)
        {
            _count = buffers.Length;
            _owned = new IntPtr[_count];
            int size = Marshal.SizeOf<SecBuffer>();
            _buffers = Marshal.AllocHGlobal(Math.Max(1, _count) * size);
            for (int i = 0; i < _count; i++)
            {
                (int type, byte[]? data) = buffers[i];
                IntPtr pv = IntPtr.Zero;
                if (data is not null)
                {
                    pv = _owned[i] = Marshal.AllocHGlobal(Math.Max(1, data.Length));
                    Marshal.Copy(data, 0, pv, data.Length);
                }
                Marshal.StructureToPtr(new SecBuffer
                {
                    cbBuffer = data?.Length ?? 0,
                    BufferType = type,
                    pvBuffer = pv,
                }, _buffers + i * size, false);
            }

            Descriptor = Marshal.AllocHGlobal(Marshal.SizeOf<SecBufferDesc>());
            Marshal.StructureToPtr(new SecBufferDesc
            {
                ulVersion = 0,
                cBuffers = _count,
                pBuffers = _buffers,
            }, Descriptor, false);
        }

        public IntPtr Descriptor { get; }

        private SecBuffer Get(int index)
            => Marshal.PtrToStructure<SecBuffer>(_buffers + index * Marshal.SizeOf<SecBuffer>());

        public byte[] Read(int index)
        {
            SecBuffer buffer = Get(index);
            byte[] data = new byte[buffer.cbBuffer];
            if (buffer.cbBuffer > 0)
            {
                Marshal.Copy(buffer.pvBuffer, data, 0, buffer.cbBuffer);
            }
            return data;
        }

        /// <summary>Reads a buffer SSPI allocated and frees it.</summary>
        public byte[] ReadAllocated(int index)
        {
            byte[] data = Read(index);
            SecBuffer buffer = Get(index);
            if (buffer.pvBuffer != IntPtr.Zero)
            {
                FreeContextBuffer(buffer.pvBuffer);
            }
            return data;
        }

        public void Dispose()
        {
            foreach (IntPtr owned in _owned)
            {
                if (owned != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(owned);
                }
            }
            Marshal.FreeHGlobal(_buffers);
            Marshal.FreeHGlobal(Descriptor);
        }
    }
}
'@
    }
}

BeforeDiscovery {
    $isAdmin = $IsWindows -and
    ([WindowsPrincipal]::new([WindowsIdentity]::GetCurrent())).IsInRole([WindowsBuiltinRole]::Administrator)
    $isSystem = $IsWindows -and [WindowsIdentity]::GetCurrent().IsSystem
}

Describe "Windows SSPI" -Skip:(-not $IsWindows) {
    BeforeAll {
        $password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
        $plainPassword = 'Password123!'

        # The SSP keeps the tickets of a supplied credential after its handle is released, and .NET caches the
        # credential handle of a NetworkCredential, so a later authentication as the same user uses those tickets
        # without contacting the KDC. A test that needs the KDC to see the exchange uses a user no other test, or an
        # earlier run of the same test in this process, has used.
        Function New-UniqueUserName {
            "user$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
        }

        # Authenticates $User@$Realm to HTTP/web.$Realm with NegotiateAuthentication requiring mutual auth, the keytab
        # acceptor returns the AP-REP the client checks.
        Function Invoke-NegotiateExchange {
            param (
                [string]$User,
                [string]$Realm,
                [byte[]]$Keytab,
                [Microsoft.Win32.SafeHandles.SafeAccessTokenHandle]$AcceptorToken
            )

            $service = "HTTP/web.$($Realm.ToLowerInvariant())"
            $client = [NegotiateAuthentication]::new([NegotiateAuthenticationClientOptions]@{
                    Package = 'Kerberos'
                    Credential = [NetworkCredential]::new("$User@$Realm", $plainPassword)
                    TargetName = $service
                    RequireMutualAuthentication = $true
                })
            try {
                $firstStatus = $status = [NegotiateAuthenticationStatusCode]::GenericFailure
                $token = $client.GetOutgoingBlob([byte[]]@(), [ref]$firstStatus)
                $accepted = [ObolTests.Sspi]::AcceptToken($token, $service, $Keytab, $AcceptorToken)
                # Without the cast PowerShell picks the string overload, which takes a base64 token.
                $null = $client.GetOutgoingBlob([byte[]]$accepted.Token, [ref]$status)

                [PSCustomObject]@{
                    AcceptorCompleted = $accepted.Completed
                    FirstStatus = $firstStatus
                    Status = $status
                    IsMutuallyAuthenticated = $client.IsMutuallyAuthenticated
                    ClientName = $accepted.ClientName
                }
            }
            finally {
                $client.Dispose()
            }
        }
    }


    AfterEach {
        Exit-ObolSspiEnvironment
        Clear-ObolSspiKdc
        Get-ObolKdc | Stop-ObolKdc
    }

    Context "NegotiateAuthentication" {
        It "Gets a Kerberos token with a password" {
            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Principal @{
                user = $password
                'HTTP/web.example.test' = $null
            } {
                $client = [NegotiateAuthentication]::new([NegotiateAuthenticationClientOptions]@{
                        Package = 'Kerberos'
                        Credential = [NetworkCredential]::new('user@EXAMPLE.TEST', $plainPassword)
                        TargetName = 'HTTP/web.example.test'
                    })
                try {
                    $status = [NegotiateAuthenticationStatusCode]::GenericFailure
                    $token = $client.GetOutgoingBlob([byte[]]@(), [ref]$status)
                    [PSCustomObject]@{ Status = $status; Token = $token }
                }
                finally {
                    $client.Dispose()
                }
            }

            $actual.Status | Should-Be ([NegotiateAuthenticationStatusCode]::Completed)
            # A GSS-API Kerberos AP-REQ, [APPLICATION 0] with the krb5 mechanism OID.
            $actual.Token[0] | Should-Be 0x60
        }

        It "Fails for a wrong password" {
            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Principal @{
                user = $password
                'HTTP/web.example.test' = $null
            } {
                $client = [NegotiateAuthentication]::new([NegotiateAuthenticationClientOptions]@{
                        Package = 'Kerberos'
                        Credential = [NetworkCredential]::new('user@EXAMPLE.TEST', 'WrongPassword')
                        TargetName = 'HTTP/web.example.test'
                    })
                try {
                    $status = [NegotiateAuthenticationStatusCode]::Completed
                    $null = $client.GetOutgoingBlob([byte[]]@(), [ref]$status)
                    $status
                }
                finally {
                    $client.Dispose()
                }
            }

            $actual | Should-NotBe ([NegotiateAuthenticationStatusCode]::Completed)
        }
    }

    Context "Ticket requests" {
        It "Gets a service ticket for a <Name>" -TestCases @(
            @{ Name = 'service with a random key'; Service = 'HTTP/web.example.test'; Target = 'HTTP/web.example.test' }
            @{ Name = 'host service'; Service = 'host/server.example.test'; Target = 'host/server.example.test' }
            @{
                Name = 'target name with the realm'
                Service = 'HTTP/web.example.test'
                Target = 'HTTP/web.example.test@EXAMPLE.TEST'
            }
        ) {
            param ($Service, $Target)

            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Principal @{ user = $password; $Service = $null } {
                [ObolTests.Sspi]::GetToken('user@EXAMPLE.TEST', $plainPassword, $Target)
            }

            $actual[0] | Should-Be 0x60
        }

        It "Gets a service ticket for a user with <EncryptionType> keys" -TestCases @(
            @{ EncryptionType = 'Aes128Sha1' }
            @{ EncryptionType = 'Aes256Sha1' }
        ) {
            param ($EncryptionType)

            # The TGT session key follows the user's keys, Windows sends an RSA-MD5 TGS-REQ checksum for either.
            $user = New-ObolPrincipalSetting -Password $password -EncryptionType $EncryptionType
            $principals = @{ user = $user; 'HTTP/web.example.test' = $null }
            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Principal $principals {
                [ObolTests.Sspi]::GetToken('user@EXAMPLE.TEST', $plainPassword, 'HTTP/web.example.test')
            }

            $actual[0] | Should-Be 0x60
        }

        It "Traces the AS and TGS exchanges of an SSPI client" {
            $user = New-UniqueUserName

            $upn = "$user@EXAMPLE.TEST"
            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Principal @{
                $user = $password
                'HTTP/web.example.test' = $null
            } {
                param ($kdc)

                # The pin is per thread and the traced scriptblock runs on this thread.
                Trace-ObolKdc -Kdc $kdc {
                    $null = [ObolTests.Sspi]::GetToken($upn, $plainPassword, 'HTTP/web.example.test')
                }
            }

            # Like kinit the SSP asks without pre-authentication first, then with the timestamp, and uses the TGT for
            # the service ticket.
            $actual.Count | Should-Be 3
            [string[]]$actual.Request.MessageType | Should-BeCollection AsReq, AsReq, TgsReq
            [string[]]$actual.Reply.MessageType | Should-BeCollection Error, AsRep, TgsRep
            [string[]]$actual.ErrorCode | Should-BeCollection PreAuthRequired, None, None
            $actual.ClientName | Should-BeCollection $upn, $upn, $upn
            $actual.ServiceName | Should-BeCollection 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST', 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST', 'HTTP/web.example.test@EXAMPLE.TEST'
            $actual.Message | Should-BeCollection @(
                "AS-REQ $upn -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: PreAuthRequired"
                "AS-REQ $upn -> krbtgt/EXAMPLE.TEST@EXAMPLE.TEST: AS-REP, Aes256Sha1 ticket and session key, PreAuthenticated, Initial, Renewable, Forwardable"
                "TGS-REQ $upn -> HTTP/web.example.test@EXAMPLE.TEST: TGS-REP, Aes256Sha1 ticket and session key, PreAuthenticated, Renewable, Forwardable"
            )

            # Windows always asks for a PAC, sends its NetBIOS name as the address and prefers AES256.
            [string[]]$actual[0].Request.PreAuthData.Type | Should-BeCollection @('PacRequest')
            $actual[0].Request.PreAuthData[0].IncludePac | Should-BeTrue
            $actual[0].Request.Body.KdcOption | Should-Be ([Obol.Kerberos.KdcOption]'Forwardable, Renewable, Canonicalize, RenewableOk')
            $actual[0].Request.Body.EncryptionType[0] | Should-Be ([Obol.Kerberos.EncryptionType]::Aes256Sha1)
            [string[]]$actual[0].Request.Body.Address.AddressType | Should-BeCollection @('NetBios')
            $actual[0].Key.Count | Should-Be 0
            # The error carries the salt and encryption types the client needs for the timestamp.
            [string[]]$actual[0].Reply.MethodData.Type | Should-BeCollection EncTimestamp, ETypeInfo2
            $etypeInfo = $actual[0].Reply.MethodData | Where-Object Type -eq ETypeInfo2
            [string[]]$etypeInfo.Entry.EncryptionType | Should-BeCollection Aes256Sha1, Aes128Sha1
            $etypeInfo.Entry.Salt | Should-BeCollection "EXAMPLE.TEST$user", "EXAMPLE.TEST$user"

            [string[]]$actual[1].Request.PreAuthData.Type | Should-BeCollection EncTimestamp, PacRequest
            $timestamp = $actual[1].Request.PreAuthData | Where-Object Type -eq EncTimestamp
            $timestamp.EncryptedData.EncryptionType | Should-Be ([Obol.Kerberos.EncryptionType]::Aes256Sha1)
            $timestamp.Timestamp | Should-HaveType ([DateTime])
            $tgt = $actual[1].Reply.Ticket.DecryptedPart
            $tgt.Flag | Should-Be ([Obol.Kerberos.TicketFlag]'PreAuthenticated, Initial, Renewable, Forwardable')
            $tgt.Pac.LogonInfo.UserName | Should-Be $user
            $tgt.Pac.LogonInfo.DomainName | Should-Be EXAMPLE
            [Convert]::ToHexString($actual[1].Reply.DecryptedPart.Key.Value) | Should-Be ([Convert]::ToHexString($tgt.Key.Value))
            $actual[1].Key.FullName | Should-BeCollection $upn, 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST'

            # PA-TGS-REQ carries the TGT, Windows adds PA-PAC-OPTIONS.
            $actual[2].Request | Should-HaveType ([Obol.Kerberos.TgsRequest])
            [string[]]$actual[2].Request.PreAuthData.Type | Should-BeCollection TgsReq, PacOptions
            $actual[2].Request.Body.KdcOption | Should-Be ([Obol.Kerberos.KdcOption]'Forwardable, Renewable, Canonicalize')
            # The authenticator has no subkey, so the restrictions Windows sends in the body's authorization data are
            # encrypted with the TGT session key.
            $actual[2].Request.Body.EncryptedAuthorizationData.EncryptionType | Should-Be ([Obol.Kerberos.EncryptionType]::Aes256Sha1)
            $apReq = $actual[2].Request.ApRequest
            $apReq.Ticket.DecryptedPart.ClientName.FullName | Should-Be $upn
            [Convert]::ToHexString($apReq.Ticket.DecryptedPart.Key.Value) | Should-Be ([Convert]::ToHexString($tgt.Key.Value))
            $apReq.Authenticator.ClientName.FullName | Should-Be $upn
            $apReq.Authenticator.Subkey | Should-BeNull
            # Windows uses the unkeyed RSA-MD5 body checksum whatever the session key type.
            $apReq.Authenticator.Checksum.ChecksumType | Should-Be ([Obol.Kerberos.ChecksumType]::RsaMd5)
            $service = $actual[2].Reply.Ticket.DecryptedPart
            $service.Key.EncryptionType | Should-Be ([Obol.Kerberos.EncryptionType]::Aes256Sha1)
            $actual[2].Reply.Ticket.EncryptedPart.EncryptionType | Should-Be ([Obol.Kerberos.EncryptionType]::Aes256Sha1)
            $service.Flag | Should-Be ([Obol.Kerberos.TicketFlag]'PreAuthenticated, Renewable, Forwardable')
            $service.Pac.LogonInfo.UserName | Should-Be $user
            $actual[2].Key.FullName | Should-BeCollection 'krbtgt/EXAMPLE.TEST@EXAMPLE.TEST', 'HTTP/web.example.test@EXAMPLE.TEST'
        }

        It "Fails for an unknown service" {
            {
                Use-ObolSspiEnvironment EXAMPLE.TEST -Principal @{ user = $password } {
                    [ObolTests.Sspi]::GetToken('user@EXAMPLE.TEST', $plainPassword, 'HTTP/missing.example.test')
                }
            } | Should-Throw -ExceptionMessage '*InitializeSecurityContext failed*'
        }
    }

    # The acceptor impersonates SYSTEM, like a Windows service, so it checks the PAC itself instead of asking a domain
    # controller. Borrowing the SYSTEM token needs an administrator.
    Context "Keytab acceptor" -Skip:(-not $isAdmin) {
        BeforeAll {
            $systemToken = [ObolTests.Sspi]::GetSystemToken()
        }

        AfterAll {
            $systemToken.Dispose()
        }

        It "Authenticates to a service with the exported keytab" {
            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Principal @{
                user = $password
                'HTTP/web.example.test' = $null
            } {
                param ($kdc)

                $keytab = $kdc | ConvertTo-ObolKeytab HTTP/web.example.test
                [ObolTests.Sspi]::Authenticate('user@EXAMPLE.TEST', $plainPassword, 'HTTP/web.example.test',
                    'HTTP/web.example.test', $keytab, $systemToken)
            }

            # The acceptor names the client from the logon domain in the PAC.
            $actual.ClientName | Should-Be 'EXAMPLE\user'
            $actual.ServerName | Should-Be 'HTTP/web.example.test@EXAMPLE.TEST'
            $actual.MutualAuth | Should-BeTrue
            $actual.EncryptionType | Should-Be 18
            $actual.WrapRoundTrip | Should-BeTrue
        }

        It "Uses a <EncryptionType> session key for a service with only those keys" -TestCases @(
            @{ EncryptionType = 'Aes128Sha1'; Expected = 17 }
            @{ EncryptionType = 'Aes256Sha1'; Expected = 18 }
        ) {
            param ($EncryptionType, $Expected)

            $service = New-ObolPrincipalSetting -EncryptionType $EncryptionType
            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Principal @{
                user = $password
                'HTTP/web.example.test' = $service
            } {
                param ($kdc)

                $keytab = $kdc | ConvertTo-ObolKeytab HTTP/web.example.test
                [ObolTests.Sspi]::Authenticate('user@EXAMPLE.TEST', $plainPassword, 'HTTP/web.example.test',
                    'HTTP/web.example.test', $keytab, $systemToken)
            }

            $actual.EncryptionType | Should-Be $Expected
            $actual.MutualAuth | Should-BeTrue
            $actual.WrapRoundTrip | Should-BeTrue
        }

        It "Issues tickets a keytab made from the password, AD salt and kvno accepts" {
            $salt = ConvertTo-ObolSalt svc_web -Realm CORP.EXAMPLE -SaltType ADUser
            $kdc = Start-ObolKdc CORP.EXAMPLE -Address 127.0.0.1 -Port 88 -Principal @{ user = $password }
            $null = $kdc | New-ObolPrincipal HTTP/web.corp.example -Password $password -Salt $salt -Kvno 7

            # Built from the password, not exported from the KDC, so the KDC must use the same salt and kvno.
            $keytab = New-ObolKeytabEntry HTTP/web.corp.example@CORP.EXAMPLE -Password $password -Salt $salt -Kvno 7 |
                ConvertTo-ObolKeytab

            $actual = Use-ObolSspiEnvironment -Kdc $kdc {
                [ObolTests.Sspi]::Authenticate('user@CORP.EXAMPLE', $plainPassword, 'HTTP/web.corp.example',
                    'HTTP/web.corp.example', $keytab, $systemToken)
            }

            $actual.ClientName | Should-Be 'CORP\user'
            $actual.MutualAuth | Should-BeTrue
            $actual.WrapRoundTrip | Should-BeTrue
        }

        It "Gets a ticket with Enter-ObolSspiEnvironment" {
            $kdc = Start-ObolKdc EXAMPLE.TEST -Address 127.0.0.1 -Port 88 -Principal @{
                user = $password
                'HTTP/web.example.test' = $null
            }
            $keytab = $kdc | ConvertTo-ObolKeytab HTTP/web.example.test

            $kdc | Enter-ObolSspiEnvironment -NoPrompt
            $actual = [ObolTests.Sspi]::Authenticate('user@EXAMPLE.TEST', $plainPassword, 'HTTP/web.example.test',
                'HTTP/web.example.test', $keytab, $systemToken)

            $actual.ClientName | Should-Be 'EXAMPLE\user'
            $actual.MutualAuth | Should-BeTrue
        }

        It "Gets a ticket with a machine binding" {
            Clear-ObolSspiKdc -Scope Machine
            try {
                $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Scope Machine -Principal @{
                    user = $password
                    'HTTP/web.example.test' = $null
                } {
                    param ($kdc)

                    $keytab = $kdc | ConvertTo-ObolKeytab HTTP/web.example.test
                    [ObolTests.Sspi]::Authenticate('user@EXAMPLE.TEST', $plainPassword, 'HTTP/web.example.test',
                        'HTTP/web.example.test', $keytab, $systemToken)
                }
            }
            finally {
                Clear-ObolSspiKdc -Scope Machine
            }

            $actual.ClientName | Should-Be 'EXAMPLE\user'
            $actual.MutualAuth | Should-BeTrue
        }

        It "Gets a ticket through the <Scope> lookup" -TestCases @(
            # A mapped realm is an MIT realm, the SSP sends no PA-DATA until the KDC asks for pre-authentication.
            # Only a KDC found by the DC locator is written to the binding cache.
            @{ Scope = 'MitRealm'; PreAuthData = ''; Binding = $null }
            @{ Scope = 'DcLocator'; PreAuthData = 'PacRequest'; Binding = '127.0.0.1' }
        ) {
            param ($Scope, $PreAuthData, $Binding)

            # A realm never used before, the DC locator also caches its results outside of the binding cache.
            $realm = "OBOL$([Guid]::NewGuid().ToString('N').Substring(0, 8).ToUpperInvariant()).TEST"
            $service = "HTTP/web.$($realm.ToLowerInvariant())"
            $actual = Use-ObolSspiEnvironment $realm -Scope $Scope -Principal @{ user = $password; $service = $null } {
                param ($kdc)

                $keytab = $kdc | ConvertTo-ObolKeytab $service
                # Trace-ObolKdc dot-sources the scriptblock, $result is set here.
                $events = Trace-ObolKdc -Kdc $kdc {
                    $result = [ObolTests.Sspi]::Authenticate("user@$realm", $plainPassword, $service, $service,
                        $keytab, $systemToken)
                }
                [PSCustomObject]@{
                    Result = $result
                    Events = $events
                    Binding = Get-ObolSspiKdc -Scope Machine | Where-Object Realm -EQ $realm
                }
            }

            $actual.Result.ClientName | Should-Be "$($realm.Split('.')[0])\user"
            $actual.Result.MutualAuth | Should-BeTrue
            $kdcEvents = @($actual.Events | Where-Object { $_ -is [Obol.ObolKdcEvent] })
            [string[]]$kdcEvents.Request.MessageType | Should-BeCollection AsReq, AsReq, TgsReq
            # RealmFlags TcpSupported for MitRealm, the DC locator always uses TCP.
            [string[]]$kdcEvents.Transport | Should-BeCollection Tcp, Tcp, Tcp
            @($kdcEvents[0].Request.PreAuthData.Type) -join ',' | Should-Be $PreAuthData

            # The DC locator finds the KDC through a DNS SRV query and checks it with an LDAP ping.
            $dnsEvents = @($actual.Events | Where-Object { $_ -is [Obol.ObolDnsEvent] })
            $ldapEvents = @($actual.Events | Where-Object { $_ -is [Obol.ObolLdapEvent] })
            $kdcHost = "kdc1.$($realm.ToLowerInvariant())"
            if ($Scope -eq 'DcLocator') {
                $srv = @($dnsEvents | Where-Object { $_.Type -eq 'Srv' -and $_.ResponseCode -eq 'NoError' })
                $srv.Count | Should-BeGreaterThan 0
                $srv[0].Answer[0].Target | Should-Be $kdcHost
                $srv[0].Message | Should-BeLikeString "SRV _*.$($realm.ToLowerInvariant()): NoError, ${kdcHost}:*"

                $ldapEvents.Count | Should-BeGreaterThan 0
                $ldapEvents[0].DnsDomain.TrimEnd('.').ToUpperInvariant() | Should-Be $realm
                $ldapEvents[0].DcHostName | Should-Be $kdcHost
                $ldapEvents[0].Kdc | Should-Be $kdcEvents[0].Kdc
            }
            else {
                $dnsEvents.Count + $ldapEvents.Count | Should-Be 0
            }
            $actual.Binding.KdcAddress | Should-Be $Binding
            Get-ObolSspiKdc -Scope Machine | Where-Object Realm -EQ $realm | Should-BeNull
        }

        It "Mutually authenticates NegotiateAuthentication to a service with the exported keytab" {
            $user = New-UniqueUserName
            $actual = Use-ObolSspiEnvironment MUTUAL.TEST -Principal @{
                $user = $password
                'HTTP/web.mutual.test' = $null
            } {
                param ($kdc)

                $keytab = $kdc | ConvertTo-ObolKeytab HTTP/web.mutual.test
                Invoke-NegotiateExchange -User $user -Realm MUTUAL.TEST -Keytab $keytab -AcceptorToken $systemToken
            }

            # With mutual auth the first token needs the AP-REP before the client is done.
            $actual.AcceptorCompleted | Should-BeTrue
            $actual.FirstStatus | Should-Be ([NegotiateAuthenticationStatusCode]::ContinueNeeded)
            $actual.Status | Should-Be ([NegotiateAuthenticationStatusCode]::Completed)
            $actual.IsMutuallyAuthenticated | Should-BeTrue
            $actual.ClientName | Should-Be "MUTUAL\$user"
        }
    }

    # Without SeTcbPrivilege the acceptor asks a domain controller of the realm to check the PAC, there is none.
    Context "Keytab acceptor without SeTcbPrivilege" -Skip:$isSystem {
        It "Fails to accept a ticket with a PAC" {
            {
                Use-ObolSspiEnvironment EXAMPLE.TEST -Principal @{
                    user = $password
                    'HTTP/web.example.test' = $null
                } {
                    param ($kdc)

                    $keytab = $kdc | ConvertTo-ObolKeytab HTTP/web.example.test
                    [ObolTests.Sspi]::Authenticate('user@EXAMPLE.TEST', $plainPassword, 'HTTP/web.example.test',
                        'HTTP/web.example.test', $keytab, $null)
                }
            } | Should-Throw -ExceptionMessage '*AcceptSecurityContext failed*'
        }

        It "Accepts a ticket for a NoAuthDataRequired service" {
            $service = New-ObolPrincipalSetting -Flag NoAuthDataRequired
            $actual = Use-ObolSspiEnvironment EXAMPLE.TEST -Principal @{
                user = $password
                'HTTP/web.example.test' = $service
            } {
                param ($kdc)

                $keytab = $kdc | ConvertTo-ObolKeytab HTTP/web.example.test
                [ObolTests.Sspi]::Authenticate('user@EXAMPLE.TEST', $plainPassword, 'HTTP/web.example.test',
                    'HTTP/web.example.test', $keytab, $null)
            }

            # Without a PAC there is no NetBIOS logon domain, Windows names the client with the realm.
            $actual.ClientName | Should-Be 'EXAMPLE.TEST\user'
            $actual.MutualAuth | Should-BeTrue
            $actual.WrapRoundTrip | Should-BeTrue
        }

        It "Mutually authenticates NegotiateAuthentication to a NoAuthDataRequired service" {
            $service = New-ObolPrincipalSetting -Flag NoAuthDataRequired
            $user = New-UniqueUserName
            $actual = Use-ObolSspiEnvironment NOPAC.TEST -Principal @{
                $user = $password
                'HTTP/web.nopac.test' = $service
            } {
                param ($kdc)

                $keytab = $kdc | ConvertTo-ObolKeytab HTTP/web.nopac.test
                Invoke-NegotiateExchange -User $user -Realm NOPAC.TEST -Keytab $keytab
            }

            $actual.AcceptorCompleted | Should-BeTrue
            $actual.Status | Should-Be ([NegotiateAuthenticationStatusCode]::Completed)
            $actual.IsMutuallyAuthenticated | Should-BeTrue
            $actual.ClientName | Should-Be "NOPAC.TEST\$user"
        }
    }
}
