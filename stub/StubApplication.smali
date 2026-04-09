.class public Lcom/trilo/stub/StubApplication;
.super Landroid/app/Application;

.source "StubApplication.smali"

# ─── Static fields ───
# Decrypted DEX buffers (set during attachBaseContext)
.field private static decryptedDexBuffers:[Ljava/nio/ByteBuffer;

# ─── Static initializer ───
.method static constructor <clinit>()V
    .registers 1
    const/4 v0, 0x0
    sput-object v0, Lcom/trilo/stub/StubApplication;->decryptedDexBuffers:[Ljava/nio/ByteBuffer;
    return-void
.end method

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/Application;-><init>()V
    return-void
.end method

# ─── attachBaseContext: main entry point ───
.method public attachBaseContext(Landroid/content/Context;)V
    .registers 10

    # Step 1: Load native library for Derive-B
    :try_start_load
    const-string v0, "trilocfg"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    :try_end_load
    .catch Ljava/lang/UnsatisfiedLinkError; {:try_start_load .. :try_end_load} :catch_lib

    # Step 2: Reconstruct master key (16 bytes)
    invoke-static {p1}, Lcom/trilo/stub/StubApplication;->reconstructMasterKey(Landroid/content/Context;)[B
    move-result-object v0

    if-eqz v0, :cond_fallback

    # Step 3: Decrypt DEX files and load into memory
    invoke-static {p1, v0}, Lcom/trilo/stub/StubApplication;->decryptAndLoadDex(Landroid/content/Context;[B)[Ljava/nio/ByteBuffer;
    move-result-object v1

    if-eqz v1, :cond_fallback

    # Step 4: Create InMemoryDexClassLoader
    const/4 v2, 0x0
    :try_start_loader
    new-instance v3, Ldalvik/system/InMemoryDexClassLoader;
    invoke-direct {v3, v1, v2}, Ldalvik/system/InMemoryDexClassLoader;-><init>([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V

    # Step 5: Install dex elements via reflection
    invoke-static {v3}, Lcom/trilo/stub/StubApplication;->installDexElements(Ldalvik/system/InMemoryDexClassLoader;)V
    :try_end_loader
    .catch Ljava/lang/Exception; {:try_start_loader .. :try_end_loader} :catch_loader

    # Step 6: Call super
    invoke-direct {p0, p1}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V
    return-void

    :catch_lib
    move-exception v0
    invoke-direct {p0, p1}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V
    return-void

    :catch_loader
    move-exception v0
    invoke-direct {p0, p1}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V
    return-void

    :cond_fallback
    invoke-direct {p0, p1}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V
    return-void
.end method

# ─── Key reconstruction ───
# Returns 16-byte master key = Derive-A ^ Derive-B ^ Derive-C
.method private static reconstructMasterKey(Landroid/content/Context;)[B
    .registers 12
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    # Derive-A: SHA-256(packageName|minSdk|targetSdk|certHash)[0:16]
    invoke-static {p0}, Lcom/trilo/stub/StubApplication;->deriveA(Landroid/content/Context;)[B
    move-result-object v0

    # Derive-B: From native library
    invoke-static {}, Lcom/trilo/stub/KeyProvider;->getKeyPart()[B
    move-result-object v1

    # Derive-C: From resource file
    invoke-static {p0}, Lcom/trilo/stub/StubApplication;->deriveC(Landroid/content/Context;)[B
    move-result-object v2

    # XOR all three together
    const/16 v3, 0x10
    new-array v4, v3, [B

    const/4 v5, 0x0
    :xor_loop
    if-ge v5, v3, :xor_done

    aget-byte v6, v0, v5
    aget-byte v7, v1, v5
    xor-int/2addr v6, v7
    aget-byte v7, v2, v5
    xor-int/2addr v6, v7
    int-to-byte v6, v6
    aput-byte v6, v4, v5

    add-int/lit8 v5, v5, 0x1
    goto :xor_loop

    :xor_done
    return-object v4
.end method

# ─── Derive-A: APK feature derivation ───
.method private static deriveA(Landroid/content/Context;)[B
    .registers 10

    # Build input string: packageName|minSdk|targetSdk|certHash
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    # packageName
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
    move-result-object v1
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "|"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    # minSdk = 26
    const/16 v1, 0x1a
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, "|"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    # targetSdk = 33
    const/16 v1, 0x21
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, "|"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    # certHash
    invoke-static {p0}, Lcom/trilo/stub/StubApplication;->getCertHash(Landroid/content/Context;)Ljava/lang/String;
    move-result-object v1
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0

    # SHA-256 hash, take first 16 bytes
    invoke-static {v0}, Lcom/trilo/stub/StubApplication;->sha256First16(Ljava/lang/String;)[B
    move-result-object v0

    return-object v0
.end method

# ─── Derive-C: Resource file decoding ───
.method private static deriveC(Landroid/content/Context;)[B
    .registers 6

    # Read assets/trilodata.bin
    invoke-virtual {p0}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;
    move-result-object v0

    const-string v1, "trilodata.bin"

    :try_read
    invoke-virtual {v0, v1}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;
    move-result-object v0

    invoke-virtual {v0}, Ljava/io/InputStream;->available()I
    move-result v1

    new-array v2, v1, [B
    const/4 v3, 0x0
    :read_loop
    invoke-virtual {v0, v2, v3, v1}, Ljava/io/InputStream;->read([BII)I
    move-result v4
    if-lez v4, :read_done
    add-int/2addr v3, v4
    sub-int/2addr v1, v4
    if-gtz v1, :read_done
    goto :read_loop
    :read_done

    invoke-virtual {v0}, Ljava/io/InputStream;->close()V

    return-object v2
    :try_end_read
    .catch Ljava/lang/Exception; {:try_read .. :try_end_read} :catch_read

    :catch_read
    move-exception v0
    const/16 v0, 0x10
    new-array v0, v0, [B
    return-object v0
.end method

# ─── Decrypt and load DEX files ───
# Reads encrypted_classes.dat and encrypted_classes2.dat from assets,
# decrypts each with AES-256-GCM, returns array of ByteBuffers.
.method private static decryptAndLoadDex(Landroid/content/Context;[B)[Ljava/nio/ByteBuffer;
    .registers 12

    # We have 2 DEX files
    const/4 v0, 0x2
    new-array v1, v0, [Ljava/nio/ByteBuffer;

    const/4 v2, 0x0
    :dex_loop
    if-ge v2, v0, :dex_done

    # Select filename based on index
    if-nez v2, :try_second
    const-string v4, "encrypted_classes.dat"
    goto :open_file
    :try_second
    const-string v4, "encrypted_classes2.dat"

    :open_file
    # Open encrypted file from assets
    invoke-virtual {p0}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;
    move-result-object v3

    :try_open
    invoke-virtual {v3, v4}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;
    move-result-object v3

    # Read all bytes
    invoke-virtual {v3}, Ljava/io/InputStream;->available()I
    move-result v4
    new-array v5, v4, [B
    const/4 v6, 0x0
    :enc_read_loop
    invoke-virtual {v3, v5, v6, v4}, Ljava/io/InputStream;->read([BII)I
    move-result v7
    if-lez v7, :enc_read_done
    add-int/2addr v6, v7
    sub-int/2addr v4, v7
    if-gtz v4, :enc_read_done
    goto :enc_read_loop
    :enc_read_done

    invoke-virtual {v3}, Ljava/io/InputStream;->close()V

    # AES-GCM decrypt
    invoke-static {v5, p1}, Lcom/trilo/stub/StubApplication;->aesGcmDecrypt([B[B)[B
    move-result-object v5

    if-eqz v5, :skip_dex

    # Wrap decrypted DEX in ByteBuffer
    array-length v6, v5
    invoke-static {v6}, Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;
    move-result-object v6
    invoke-virtual {v6, v5}, Ljava/nio/ByteBuffer;->put([B)Ljava/nio/ByteBuffer;
    const/4 v7, 0x0
    invoke-virtual {v6, v7}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    aput-object v6, v1, v2
    :skip_dex

    add-int/lit8 v2, v2, 0x1
    goto :dex_loop

    :dex_done
    sput-object v1, Lcom/trilo/stub/StubApplication;->decryptedDexBuffers:[Ljava/nio/ByteBuffer;
    return-object v1

    .catch Ljava/io/IOException; {:try_open .. :enc_read_done} :catch_io
    :catch_io
    move-exception v0
    const/4 v0, 0x0
    return-object v0
.end method

# ─── AES-256-GCM decrypt ───
# Input: [12B nonce][ciphertext + 16B GCM tag]
# Returns: plaintext or null on failure
.method private static aesGcmDecrypt([B[B)[B
    .registers 10

    # Extract nonce (first 12 bytes)
    const/16 v0, 0xc
    new-array v1, v0, [B
    const/4 v2, 0x0
    :copy_nonce
    if-ge v2, v0, :nonce_done
    aget-byte v3, p0, v2
    aput-byte v3, v1, v2
    add-int/lit8 v2, v2, 0x1
    goto :copy_nonce
    :nonce_done

    # Extract ciphertext+tag (remaining bytes)
    array-length v2, p0
    sub-int/2addr v2, v0
    new-array v3, v2, [B
    const/16 v4, 0xc
    const/4 v5, 0x0
    :copy_ct
    if-ge v5, v2, :ct_done
    add-int v6, v4, v5
    aget-byte v7, p0, v6
    aput-byte v7, v3, v5
    add-int/lit8 v5, v5, 0x1
    goto :copy_ct
    :ct_done

    # Create SecretKeySpec
    new-instance v4, Ljavax/crypto/spec/SecretKeySpec;
    const-string v5, "AES"
    invoke-direct {v4, p1, v5}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    # Create GCMParameterSpec (128-bit tag)
    new-instance v5, Ljavax/crypto/spec/GCMParameterSpec;
    const/16 v6, 0x80
    invoke-direct {v5, v6, v1}, Ljavax/crypto/spec/GCMParameterSpec;-><init>(I[B)V

    # Cipher.getInstance("AES/GCM/NoPadding")
    const-string v1, "AES/GCM/NoPadding"
    invoke-static {v1}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v1

    # cipher.init(DECRYPT_MODE, key, gcmSpec)
    const/4 v6, 0x2
    invoke-virtual {v1, v6, v4, v5}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    # cipher.doFinal(ciphertext) -> plaintext
    invoke-virtual {v1, v3}, Ljavax/crypto/Cipher;->doFinal([B)[B
    move-result-object v0

    return-object v0

    .catch Ljava/lang/Exception; {:copy_nonce .. :ct_done} :catch_fail
    :catch_fail
    move-exception v0
    const/4 v0, 0x0
    return-object v0
.end method

# ─── Install dex elements via reflection ───
.method private static installDexElements(Ldalvik/system/InMemoryDexClassLoader;)V
    .registers 12
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    # Get context's classLoader (PathClassLoader)
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;
    move-result-object v0
    invoke-virtual {v0}, Ljava/lang/Thread;->getContextClassLoader()Ljava/lang/ClassLoader;
    move-result-object v0

    # Get pathList field from BaseDexClassLoader
    const-class v1, Ldalvik/system/BaseDexClassLoader;
    const-string v2, "pathList"
    invoke-virtual {v1, v2}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;
    move-result-object v1

    const/4 v3, 0x1
    invoke-virtual {v1, v3}, Ljava/lang/reflect/Field;->setAccessible(Z)V

    # Get pathList from memoryLoader
    invoke-virtual {v1, p0}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;
    move-result-object v4

    # Get dexElements field
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    move-result-object v5
    const-string v6, "dexElements"
    invoke-virtual {v5, v6}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;
    move-result-object v5

    invoke-virtual {v5, v3}, Ljava/lang/reflect/Field;->setAccessible(Z)V

    # Get stub elements
    invoke-virtual {v5, v4}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;
    move-result-object v7
    check-cast v7, [Ljava/lang/Object;

    # Get original elements from pathClassLoader
    invoke-virtual {v1, v0}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;
    move-result-object v8

    invoke-virtual {v5, v8}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;
    move-result-object v8
    check-cast v8, [Ljava/lang/Object;

    # Merge arrays: stub + original
    array-length v9, v7
    array-length v10, v8
    add-int/2addr v9, v10
    new-array v9, v9, [Ljava/lang/Object;

    # Copy stub elements first
    const/4 v10, 0x0
    array-length v11, v7
    invoke-static {v7, v10, v9, v10, v11}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    # Copy original elements after stub
    array-length v10, v7
    const/4 v11, 0x0
    array-length v12, v8
    invoke-static {v8, v11, v9, v10, v12}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    # Write merged array back to pathClassLoader
    invoke-virtual {v5, v8, v9}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V
.end method

# ─── Helper: Get certificate hash ───
.method private static getCertHash(Landroid/content/Context;)Ljava/lang/String;
    .registers 8

    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;
    move-result-object v0

    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
    move-result-object v1

    const/16 v2, 0x40

    :try_cert
    invoke-virtual {v0, v1, v2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;
    move-result-object v0

    iget-object v0, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    const/4 v1, 0x0
    aget-object v0, v0, v1

    invoke-virtual {v0}, Landroid/content/pm/Signature;->toByteArray()[B
    move-result-object v0

    invoke-static {v0}, Lcom/trilo/stub/StubApplication;->sha256Hex([B)Ljava/lang/String;
    move-result-object v0

    return-object v0
    :try_end_cert
    .catch Ljava/lang/Exception; {:try_cert .. :try_end_cert} :catch_cert

    :catch_cert
    move-exception v0
    const-string v0, ""
    return-object v0
.end method

# ─── Helper: SHA-256 first 16 bytes ───
.method private static sha256First16(Ljava/lang/String;)[B
    .registers 6

    invoke-virtual {p0}, Ljava/lang/String;->getBytes()[B
    move-result-object v0

    const-string v1, "SHA-256"
    invoke-static {v1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/security/MessageDigest;->digest([B)[B
    move-result-object v0

    const/16 v1, 0x10
    new-array v2, v1, [B
    const/4 v3, 0x0
    :copy16
    if-ge v3, v1, :done16
    aget-byte v4, v0, v3
    aput-byte v4, v2, v3
    add-int/lit8 v3, v3, 0x1
    goto :copy16
    :done16
    return-object v2
.end method

# ─── Helper: SHA-256 to hex string ───
.method private static sha256Hex([B)Ljava/lang/String;
    .registers 7

    const-string v0, "SHA-256"
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v0

    invoke-virtual {v0, p0}, Ljava/security/MessageDigest;->digest([B)[B
    move-result-object p0

    new-instance v0, Ljava/lang/StringBuilder;
    array-length v1, p0
    mul-int/lit8 v1, v1, 0x2
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "%02x"
    array-length v2, p0
    const/4 v3, 0x0
    :hex_loop
    if-ge v3, v2, :hex_done

    const/4 v4, 0x1
    new-array v4, v4, [Ljava/lang/Object;
    aget-byte v5, p0, v3
    invoke-static {v5}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;
    move-result-object v5
    const/4 v6, 0x0
    aput-object v5, v4, v6

    invoke-static {v1, v4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;
    move-result-object v4

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    add-int/lit8 v3, v3, 0x1
    goto :hex_loop

    :hex_done
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
