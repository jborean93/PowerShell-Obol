using System;
using System.Buffers.Binary;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Obol.Tests;

/// <summary>
/// Known answer tests for the Kerberos.NET cryptography Obol uses, so a change in the dependency cannot go unnoticed
/// by only comparing its output with itself.
/// </summary>
/// <remarks>
/// The RFC 3962 and RFC 8009 vectors are from the RFC appendixes. The MIT vectors were made with libkrb5
/// krb5_c_encrypt and krb5_c_make_checksum for each key usage Obol uses, encryption is random so a ciphertext is
/// checked by decrypting it.
/// </remarks>
public class CryptoVectorTests
{
    /// <summary>
    /// The plaintext of the MIT vectors, not a multiple of the block size so ciphertext stealing is used.
    /// </summary>
    private const string MitPlaintext =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f4f626f6c";

    private static byte[] Hex(string value) => Convert.FromHexString(value);

    /// <summary>
    /// Derives a key from a password like <c>PrincipalStore</c>, with the salt and iteration count given.
    /// </summary>
    private static byte[] StringToKey(string password, byte[] salt, int iterations, EncryptionType etype)
    {
        byte[] iterationParams = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(iterationParams, iterations);
        KerberosKey key = new(
            password: Encoding.Unicode.GetBytes(password),
            saltBytes: salt,
            etype: etype,
            iterationParams: iterationParams);
        return key.GetKey().ToArray();
    }

    [Test]
    [Arguments("password", "ATHENA.MIT.EDUraeburn", null, 1,
        "42263c6e89f4fc28b8df68ee09799f15",
        "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161")]
    [Arguments("password", "ATHENA.MIT.EDUraeburn", null, 2,
        "c651bf29e2300ac27fa469d693bdda13",
        "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff")]
    [Arguments("password", "ATHENA.MIT.EDUraeburn", null, 1200,
        "4c01cd46d632d01e6dbe230a01ed642a",
        "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a")]
    [Arguments("password", null, "1234567878563412", 5,
        "e9b23d52273747dd5c35cb55be619d8e",
        "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31")]
    [Arguments("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase equals block size",
        null, 1200,
        "59d1bb789a828b1aa54ef9c2883f69ed",
        "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34")]
    [Arguments("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase exceeds block size",
        null, 1200,
        "cb8005dc5f90179a7f02104c0018751d",
        "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b")]
    [Arguments("\U0001D11E", "EXAMPLE.COMpianist", null, 50,
        "f149c1f2e154a73452d43e7fe62a56e5",
        "4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e")]
    public async Task DerivesRfc3962Keys(
        string password,
        string? salt,
        string? saltHex,
        int iterations,
        string aes128,
        string aes256)
    {
        byte[] saltBytes = saltHex is null ? Encoding.UTF8.GetBytes(salt!) : Hex(saltHex);

        await Assert.That(Convert.ToHexStringLower(
            StringToKey(password, saltBytes, iterations, EncryptionType.AES128_CTS_HMAC_SHA1_96))).IsEqualTo(aes128);
        await Assert.That(Convert.ToHexStringLower(
            StringToKey(password, saltBytes, iterations, EncryptionType.AES256_CTS_HMAC_SHA1_96))).IsEqualTo(aes256);
    }

    [Test]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, "089bca48b105ea6ea77ca5d2f39dc5e7")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192,
        "45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467")]
    public async Task DerivesRfc8009Keys(EncryptionType etype, string expected)
    {
        // The RFC salt is 16 random bytes and the realm and name, the enctype name prefix is added by the KDF.
        byte[] salt = [.. Hex("10df9dd783e5bc8acea1730e74355f61"), .. Encoding.UTF8.GetBytes("ATHENA.MIT.EDUraeburn")];

        byte[] key = StringToKey("password", salt, 32768, etype);

        await Assert.That(Convert.ToHexStringLower(key)).IsEqualTo(expected);
    }

    [Test]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, "",
        "ef85fb890bb8472f4dab20394dca781dad877eda39d50c870c0d5a0a8e48c718")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, "000102030405060708090a0b0c0d0e0f",
        "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc295fb4852e7d83e1e7c48c37eebe6b0d3")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, "000102030405060708090a0b0c0d0e0f1011121314",
        "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c186b39a413c2f92ca9b8334a287ffcbfc")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, "",
        "41f53fa5bfe7026d91faf9be959195a058707273a96a40f0a01960621ac612748b9bbfbe7eb4ce3c")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, "000102030405060708090a0b0c0d0e0f",
        "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f6" +
        "8cf51f14d798c2273f35df574d1f932e40c4ff255b36a266")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, "000102030405060708090a0b0c0d0e0f1011121314",
        "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2" +
        "b2a602ac86fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62")]
    public async Task DecryptsRfc8009Vectors(EncryptionType etype, string plaintext, string ciphertext)
    {
        // The sample encryptions use the base key of the key derivation samples with key usage 2.
        KerberosKey key = new(key: Hex(Rfc8009BaseKey(etype)), etype: etype);
        KrbEncryptedData encrypted = new() { EType = etype, Cipher = Hex(ciphertext) };

        byte[] actual = encrypted.Decrypt(key, KeyUsage.Ticket, b => b.ToArray());

        await Assert.That(Convert.ToHexStringLower(actual)).IsEqualTo(plaintext);
    }

    /// <summary>
    /// Kerberos.NET AESCTS.Decrypt only swaps the last two blocks back when the unpadded length is two blocks, so a
    /// confounder and plaintext between 17 and 31 bytes decrypts wrongly, the SHA-1 types then fail the HMAC and the
    /// SHA-2 types return the wrong plaintext. Kerberos messages are always longer so Obol is not affected.
    /// </summary>
    private const string ShortPlaintextBug =
        "Kerberos.NET AESCTS.Decrypt does not handle a confounder and plaintext of 17 to 31 bytes";

    [Test]
    [Skip(ShortPlaintextBug)]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, "000102030405",
        "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6877ce99e247e52d16ed4421dfdf8976c")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, "000102030405",
        "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2")]
    public async Task DecryptsRfc8009ShortVectors(EncryptionType etype, string plaintext, string ciphertext)
        => await DecryptsRfc8009Vectors(etype, plaintext, ciphertext);

    [Test]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, ChecksumType.HMAC_SHA256_128_AES128,
        "d78367186643d67b411cba9139fc1dee")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, ChecksumType.HMAC_SHA384_192_AES256,
        "45ee791567eefca37f4ac1e0222de80d43c3bfa06699672a")]
    public async Task MakesRfc8009Checksums(EncryptionType etype, ChecksumType type, string expected)
    {
        KerberosKey key = new(key: Hex(Rfc8009BaseKey(etype)), etype: etype);

        KrbChecksum checksum = KrbChecksum.Create(Hex("000102030405060708090a0b0c0d0e0f1011121314"), key,
            KeyUsage.Ticket, type);

        await Assert.That(Convert.ToHexStringLower(checksum.Checksum.Span)).IsEqualTo(expected);
    }

    /// <summary>The base key of the RFC 8009 key derivation samples.</summary>
    private static string Rfc8009BaseKey(EncryptionType etype) => etype == EncryptionType.AES128_CTS_HMAC_SHA256_128
        ? "3705d96080c17728a0e800eab6e0d23c"
        : "6d404d37faf79f9df0d33568d3206698" + "00eb4836472ea8a026d16b7182460c52";

    /// <summary>The key of the MIT vectors for the encryption type.</summary>
    private static string MitKey(EncryptionType etype) => etype switch
    {
        EncryptionType.AES128_CTS_HMAC_SHA1_96 => "101112131415161718191a1b1c1d1e1f",
        EncryptionType.AES256_CTS_HMAC_SHA1_96 => "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        EncryptionType.AES128_CTS_HMAC_SHA256_128 => "303132333435363738393a3b3c3d3e3f",
        EncryptionType.AES256_CTS_HMAC_SHA384_192 => "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        _ => throw new ArgumentOutOfRangeException(nameof(etype)),
    };

    [Test]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 1,
        "ea17af4da43c4f7c380084c0ad10c9184a1ae671c9ee2768ed000b657cb10445" +
        "95ef498051179e216ec5279471ae27f932376bfacb5d7a7c33ad5c0d3c05e201" +
        "0dc854cb878ddde665416d04d860f667")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 2,
        "bdca2c557a1404edec278edf201930350156bf1611c1ae2015fc4bb50fec79a2" +
        "83a05344b698f6d37fb83a87cce3f1fd788d8384ebb163cfbd5da99829342af9" +
        "7dca84b2458a996b2718e69be8f73b94")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 3,
        "39a9b185c628ff7a0a73c1294d0b762991273e8fb89a971cfc6846f2a78ffdff" +
        "b4e7936efa1e12b4e2b4937de9294f43cae9dbdde5630fd2bb40e698077fe81d" +
        "e9f07697e9408fb103d44948fb1ec543")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 7,
        "f33dc15383b916301716d96097682eb00430aaaee9e106f2dc1b71a0190f7c8f" +
        "545ae59008a8ff5a82f857e5440e3cc0cc9d0955dfb6096d70641adb78f80382" +
        "14503930ca7bb96258aab750a692f556")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 8,
        "c3c2621e2f8d942f8fb3b10f7ee42c6de7e24716ffc0627ee15c53c4d09a1dfc" +
        "ab25a7a3f3d08a7a859ef7db919778a8ad76465950aa7899e7d75e35d325d116" +
        "64fc74db7f27c3bfa0a19a4a5245b214")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 9,
        "c4a346ec32fc4000b74a822611206b9037289ca11e0e49abb426d1b971d4d02b" +
        "ece897a704f2bccaa57f5fd03589ddfc1454e25de82ee031ededa3991251a4eb" +
        "4cd48c36edd63505eb0c3f602cab1d8e")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 1,
        "7236756b9e0102b3a03b3069a80c22c5d3597acdbdd11d90ba8ced2fd15ba27f" +
        "08693ca776e9cace44306ee75bdb44cd904dc4ac0b4fd4daba5e42a0b78a74c4" +
        "6e3710fb58f4726037c088051fe4ee1f")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 2,
        "a7117f0e8c51f8da79b392e7613cee440934e3cf35aa7c5b1563417974512186" +
        "1d550bf6c0aedd748c941b1340305ef379256ff60f676500545b15554ca445b8" +
        "2abe04e9db5c2aa859bc53f8ccfe4b76")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 3,
        "a477f132680ceef51d223f2312e5fc452af0afdd28937dd687d3301b12db32f5" +
        "0436a3d46e20e7709994daeb369296262249e309552372972a8e265a47d1829d" +
        "f561627d2160caaaae8fba1970ccf7b2")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 7,
        "c0b76331046b9177a2fdc01aa702c523014154856cd91c313edf21c1d786fd0f" +
        "48cd0942bd14754cb526c8b7ddef3327c3abc0b32556012cb82bef1ed435e232" +
        "45ff03cac2136489a0e0e53a5ef49235")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 8,
        "b8b899ff27d929f50b32c5b54cffac037e00b6e17541f4872ebc07187a0fd5a0" +
        "8dc45f52947a458f9571fe9ba56ddc447c4b94b450d565a2f5d9e3d55f16b83d" +
        "f43cc46d4f408d1cc5fba66e6a07637c")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 9,
        "fbc3ceec0911af45cccbd1595a51a0b68ddebe53766a8b26800883a4d9790e54" +
        "fbd39188806e64beb3475c1fb5074362dca84ca87d873e91485b8c0da0d8b3a2" +
        "7f8fd3e571c37e233263a63e7158051f")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 1,
        "725c233ad4048b78b4ecb1a48aabe71771172a92e4cc4d2452654a6aadf2b77f" +
        "cdc5757b62401b87734057e9da1bf6aee290f773541630826f6ffad9bacbdbf5" +
        "1fe527f84dd0f7d22c128fa75f8f007a2741de54")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 2,
        "8f1b367f4bd18027651063f2484e5c7ff577ed8fb85a891d079082216d1d2bac" +
        "8b19074cfddeb81baf923248f03c0d45b278999705650c5a35b4901da07a9476" +
        "53d2f1a07867f940ca13ce7a03a02c891db9dbb8")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 3,
        "cc0c490436995afa6c6effc8d39c2ff8cca81144e7e0c01184454510e1cc550a" +
        "0917e1c0a0543f6558955b0ffd01a89d017d784cfd8f8008849e061dda0ec760" +
        "d7424195a04a1c11fd51a691bee81905e7088728")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 7,
        "faca498f3d5ef5ddd8d965ace8048e2708e8c651f6cb8d5245a7629403af3b63" +
        "b455615f1e65a1c8a0790ffe82c183a0ceec607d1b519074044d5ad1077e3efd" +
        "ef72edf00a3216651ffd43e106632eb4a60478c5")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 8,
        "a8f2134a924baa305ad94423b1d9e05ec2fd31ad6df09ad4db0c4c7181f5eaca" +
        "6085bd0fc4ea7f77893ba9e1c454bceacfb56de5017c38ca6d1483185f77eb2c" +
        "1ac542caeac17d576404ab969a8cfa04704942e6")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 9,
        "7b4e0a93d2c132c11c6a521f2914199eac003b9ea5dc9f30c27d5a078a17f742" +
        "3dcc04d5b470066cf35de7f969884383aa6d185a2bd8531193aa23b3487e4cdb" +
        "fc8add2724465c949ede51b018262f8c057e3c3d")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 1,
        "6507fe41f7139528daa32d3804ef2e6bf739404baff206a23994889617a25eb7" +
        "de7763e651b576c8c7f2533bd7efcb1d38b1b2384dc4fd287c9a6282cde4112d" +
        "4a7f2c5f3d7e9f54c7f0c0c00f97d191b0c4d6e02d64cd20048fd5df")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 2,
        "dfd97e081e4aca23c29f04dbdc6f8841b4f913fa55b6921bd970bdce8f7543e1" +
        "68bc436480e029b4f982b16cb7575b41898989eba17c1b7ff5af3536f986eb83" +
        "efc57511f9fab4d4584ff2633d317fee44749ca5c3ecd73a07a263bd")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 3,
        "7c8bb701b6442f44cd5995c1b5c3bb219568cfe30f3df989cd7723fe6e85cc43" +
        "bbb3e0936abc06d3db4939e5d7ecda581559715418ff6112a9b1bfd9d863e9c0" +
        "d875c5e9cd3267ffc18e50a2a61686f4b3aa8f84601065abe1ea479b")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 7,
        "8127cd2c5c1cd8a2932f45932a100350e8f10f75f2ea5603af16e7aeeda72c19" +
        "664dbd566213e0ebcf26bbe20ac13350f847bf9fe409b4f16474d0f8d02a08b6" +
        "ca734a85ecc48c9b6ce26975207e40262070aeabaaf5e41a0e196870")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 8,
        "e7a49a6e11f95d0b203e4a12e33e78f1c2b124f18c225d4ab3e8671753ac90aa" +
        "db5e4217941ef2922fd5ae7922ec4c5e649d0da0d481897ed54f5da71d2edcf8" +
        "3e97c9ea13a17c75db1beb6fd6960337cfacce22af4fe49c19a1c0d8")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 9,
        "e3f38c17f2426b949efcebc546474e0cfddce81da5963d117a44bbaf84a21ed0" +
        "40bb0c05cdb644dc4192c56c9937acebcd1665c57c0c76f77554dda2357f6948" +
        "25dbea7d1efc0c5547c100e4fb75235275a0d2fb8253a5c879507071")]
    public async Task DecryptsMitCiphertext(EncryptionType etype, int usage, string ciphertext)
    {
        // Key usages 1 PA-ENC-TIMESTAMP, 2 ticket, 3 AS-REP, 7 TGS-REQ authenticator, 8 and 9 TGS-REP.
        KerberosKey key = new(key: Hex(MitKey(etype)), etype: etype);
        KrbEncryptedData encrypted = new() { EType = etype, Cipher = Hex(ciphertext) };

        byte[] actual = encrypted.Decrypt(key, (KeyUsage)usage, b => b.ToArray());

        await Assert.That(Convert.ToHexStringLower(actual)).IsEqualTo(MitPlaintext);
    }

    [Test]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, ChecksumType.HMAC_SHA1_96_AES128, 6, "7861f50a3c85efaeb0598efb")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, ChecksumType.HMAC_SHA1_96_AES128, 17,
        "43cddb0eb585a03953e7308f")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, ChecksumType.HMAC_SHA1_96_AES256, 6, "1d8d02f5da71e449e5784694")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, ChecksumType.HMAC_SHA1_96_AES256, 17,
        "12491f3c5e3a5177a4ea05e1")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, ChecksumType.HMAC_SHA256_128_AES128, 6,
        "3e9d972fb7f8549ce8edfe62a76d8bee")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, ChecksumType.HMAC_SHA256_128_AES128, 17,
        "4f1b9371028cb33ed3c87d6e8c559b9d")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, ChecksumType.HMAC_SHA384_192_AES256, 6,
        "d6e7965f180563530d80897b569aa8281ab704f0fec7adcc")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, ChecksumType.HMAC_SHA384_192_AES256, 17,
        "df810a59fb0b5c6b4fe7ffb0332499cdf7395c3a82dceaef")]
    public async Task MakesMitChecksums(EncryptionType etype, ChecksumType type, int usage, string expected)
    {
        // Key usages 6 TGS-REQ body checksum and 17 PAC signatures.
        KerberosKey key = new(key: Hex(MitKey(etype)), etype: etype);

        KrbChecksum checksum = KrbChecksum.Create(Hex(MitPlaintext), key, (KeyUsage)usage, type);

        await Assert.That(Convert.ToHexStringLower(checksum.Checksum.Span)).IsEqualTo(expected);
    }

    [Test]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 0,
        "1664670522562bbc63c217fd0fd677adbc5dea7e1f0f80a7745ca9ba")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 16,
        "e20edb7e2e8eae82bf820fcb312635fadf587bf566010091bad2ab0c01e283d2c0067be3918a63baec60feab")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 17,
        "3586a694f24b43ff35c36a388152ac42073b68cb0181091779e13e028e142b0deceacf8e2405e280da12daef1b")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 31,
        "a5c19667b7af62172e2d234f52910f797ec4a12138a11b967c13d8bdb7102c1a" +
        "51114c6f33f399fe5dba3bb84dc03bd1ed5fee374dfcd99896dd01")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 32,
        "e7f76e1c65efc5e9bc6e67bdbf7a17353294b3173b8e7ced256afeb63edcd383" +
        "b7ea8e8c7f88c20b5c00f75de9a5c385bfa5affb89c9ea424f1433b6")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 33,
        "0a4a6a69555b549cb50784911825630cf501cfdc361fb9bc67a2e587e7d98301" +
        "b86c751d7abbdcbd901f5e722d56765897ad399bd48e5378bdd2425e71")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 0,
        "0dde9aa4591afc42f7d18636c69e9bcd3066263a1d494e3e3e93bdac")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 16,
        "4183b7ebde718676c98c7188f3837d1fb630732896533642192b0f764b1e2f993c02e2aa536b864afe64a016")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 17,
        "3e21f7e6b0a796a73a146076d5d9803d9bcdaff844252ef5bb3b189c6d8ff12173d6147be0637d113459757523")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 31,
        "3f3c051e33d3734ac3f4e5ec26dcbf47615dc56ba8d1f87553b9a3a532a08963" +
        "0c1311dfea9d8fe37712195deda5d9e09ce379aae9d8f8fca3f443")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 32,
        "928ac5e0f41d88d606f5b9fb073844576741229655956d2e30a7c047cf306b1d" +
        "539490daab8cd569eaa260f8efbbbcb305dc6455be41aad68a717c5b")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 33,
        "dcb00967e2868ad7c9ba69d3079e8ab11242f526fa9463b3c4110539f0c135b6" +
        "4f66f8aadc96bddb98b53630a33ef8a313a7eb62c75c7b3d4157dd6da3")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 0,
        "aa512964c2583e39b008b1e6b0edc398d7058052139216c3fec95aa7222ec600")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 16,
        "d774b71b20f2bab77fc1d7ebd0acac0c0b0ceb7e702b0c361b4c79a0031375f9" +
        "9d351a596c42c38566dbeeb397c30b87")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 17,
        "913dda437957781ab4ccc9a5f3d130ae439521afea5eeac2496b4a0a246b5704" +
        "e49dd92ab6b21afe5e559265abec40605d")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 31,
        "9149839ff6b5e882ee1f30402ae79ab0839e6508669f684feb6d2f30236ec904" +
        "a8882c0c6fe7c713cddba8c1884c4eae2075d5f2855bd0e1cbb8233b4a25d6")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 32,
        "a125cd60c6e4e9b75f549ef3f31bb566165b2296ecf397980b7129587ad8f9b0" +
        "7f181a54de04b9ffead91ce247fa75e592d98b0f2a900b688e169723102168e8")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 33,
        "f0dbc4622bd68948828f0145999411b4ab2a1229f77d1dda6570a8cb885584bd" +
        "6d5c27f4417926c06566aab972cc05db1e9986a30f643bd2d0b8c27ee432bd1b" +
        "92")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 0,
        "3817ed78ad2f472eb5f6fb83adf7fc7664eff17d2d70cea4355febcd7458fe630245a62fb354850f")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 16,
        "debd642f43588ac8199220afc39e1ebac0dabd4a290d5429cf8df67efe274817" +
        "ad4ba00c3cd13a831f5477e1d20d46c9e5f92cbec7e80148")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 17,
        "040a26d92305a11e4b5348ab22df995ae74528184303169d755ebf236dfbdf20" +
        "357acd4023c65256abc82cf294ded8b24cc370e0e32c83caf5")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 31,
        "dde4ffb3c698d2f5d8339566929ee6190b3fddde9c2cf2339f8cf38b38792227" +
        "ca39a72459fa99d9e50118eca1f1c6e2c67ac34bd0c2654fbc43bfb3fb2ccff0" +
        "e73fb738937332")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 32,
        "c75669719f5281dac5a9dc9dcb90b6e8c47587e23c2842a498931af87e21f0af" +
        "097ead7421f9740202868b9d0e0859fc3d2c050c3c70f96ff49a8b8994831df1" +
        "b1d538d1cb44f404")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 33,
        "3dbcd58505e87769dea9f8c9068f3239227510cf198bee95a84694e6828abfe6" +
        "a76dd83db7079235899ca7bfcdd99f2905a0bf73589f7155abff8f9fc82ff595" +
        "a2b7b5158fd312efb7")]
    public async Task DecryptsMitCiphertextAroundBlockSize(EncryptionType etype, int length, string ciphertext)
    {
        // A plaintext of 0..length bytes, around the AES block size where ciphertext stealing changes.
        KerberosKey key = new(key: Hex(MitKey(etype)), etype: etype);
        KrbEncryptedData encrypted = new() { EType = etype, Cipher = Hex(ciphertext) };

        byte[] actual = encrypted.Decrypt(key, KeyUsage.Ticket, b => b.ToArray());

        await Assert.That(actual).IsEquivalentTo(Enumerable.Range(0, length).Select(i => (byte)i).ToArray());
    }

    [Test]
    [Skip(ShortPlaintextBug)]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 1,
        "6632dd7027c35614f3e9dc60522eefd7277618f74aa2a614af710bb346")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 6,
        "5abca6a288781dc8cddf8a81879daf91f690d06ebada08925cc49e28c5eaff8e901b")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA1_96, 15,
        "9f7a65617ee7768ba67d1488f3bfffea476b180c181b6343b635bb4b68362d341c4aeac802b77335476456")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 1,
        "6e57abcafcecc1f57bf274fb6e09c67ee707ea497f2e62c65804f51bc7")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 6,
        "98bfcac372853c5454682eab2bfae43c672ca80c1cdbffca1849094bada6d3ec6205")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA1_96, 15,
        "4e917464bc7da86a33cf60aac6ccbdb9e1cee5c54ec2e1ab19a68c5ee3cf410e69df090f0dd41c495c7aab")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 1,
        "54d47a51f94bfc11383eeb7f114f17c8a7fb9143e555bdda10a023079692fd6b10")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 6,
        "b472db80ebf792db6e71f0d3e553357e75d8f629a0c4b238c341b3a40ca0e25a3e8cbbbddd30")]
    [Arguments(EncryptionType.AES128_CTS_HMAC_SHA256_128, 15,
        "7ee83d7aa37076cf6d92b64e9cbe597dc68d784ef80646a3f74f9b392f1e593c" +
        "f5612e06573cae35c15e24bdbb86de")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 1,
        "b2b2bd5378e165468d10b8c6c56db624dc80930ea6de2edd612635fd1d85ebcf07f5fa7ff26d1beee4")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 6,
        "36bf397710970a036826514295c19550d0b98cf8d38dcdc9295bbe8232531126" +
        "e7ac1972d2e4e29af2abd96d636d")]
    [Arguments(EncryptionType.AES256_CTS_HMAC_SHA384_192, 15,
        "34733b0ee7233fbe04a90d7818cc9d1c2d2486ac4a500b6ab5fb8074173cc2c0" +
        "d59dbae606e8047f660037d4ae02d4e9aa376e1884af18")]
    public async Task DecryptsMitCiphertextShorterThanBlockSize(EncryptionType etype, int length, string ciphertext)
        => await DecryptsMitCiphertextAroundBlockSize(etype, length, ciphertext);
}
