//
//  Type42.swift
//  SwiftBSV
//
//  BRC-42 Type42 key derivation using ECDH shared secrets.
//  Modern replacement for BIP32 integer-path derivation.
//
//  Algorithm:
//  1. sharedSecret = SHA256(myPrivateKey * counterpartyPublicKey)
//  2. hmac = HMAC-SHA256(sharedSecret, invoiceNumber)
//  3. childPrivateKey = (masterPrivateKey + hmac) mod N
//
//  For public key only derivation:
//  3. childPublicKey = masterPublicKey + hmac * G
//
//  Reference: BRC-42 specification
//  Compatible with: @bsv/sdk Type42 key derivation
//

import Foundation
import CryptoSwift

public struct Type42 {

    // secp256k1 curve order
    // swiftlint:disable:next identifier_name
    private static let N = BInt("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", radix: 16)!

    // MARK: - Core Derivation

    /// Derive a child private key using Type42 (BRC-42).
    /// - Parameters:
    ///   - privateKey: The master private key
    ///   - counterpartyPublicKey: The counterparty's public key (use own pubkey for self-derivation)
    ///   - invoiceNumber: Any string identifying the purpose (e.g. "1-bap-identity", "payment-001")
    /// - Returns: The derived child private key, or nil on failure
    public static func derivePrivateKey(
        privateKey: PrivateKey,
        counterpartyPublicKey: PublicKey,
        invoiceNumber: String
    ) -> PrivateKey? {
        // Step 1: ECDH — multiply counterparty's public key by our private key
        guard let sharedPoint = ecdhSharedSecret(privateKey: privateKey, publicKey: counterpartyPublicKey) else {
            return nil
        }

        // Step 2: SHA256 the shared point to get a 32-byte shared secret.
        // Uses full 33-byte compressed point (02/03 prefix + x-coordinate),
        // matching @bsv/sdk canonical BRC-42 implementation.
        let sharedSecret = Data(sharedPoint).sha256()

        // Step 3: HMAC-SHA256(sharedSecret, invoiceNumber) to get the tweak
        guard let invoiceData = invoiceNumber.data(using: .utf8) else {
            return nil
        }
        let hmac = hmacSHA256(key: sharedSecret, data: invoiceData)

        // Step 4: childPrivKey = (masterPrivKey + hmac) mod N
        do {
            var paddedKey = padTo32Bytes(privateKey.data)
            var tweakedBytes = try Secp256k1.privateKeyTweakAdd(paddedKey, tweak: [UInt8](hmac))
            let childKey = PrivateKey(data: Data(tweakedBytes))
            // Zero intermediate key material
            for i in paddedKey.indices { paddedKey[i] = 0 }
            for i in tweakedBytes.indices { tweakedBytes[i] = 0 }
            return childKey
        } catch {
            return nil
        }
    }

    /// Derive a child public key using Type42 (BRC-42) — no private key needed.
    /// - Parameters:
    ///   - publicKey: The master public key
    ///   - ownPrivateKey: Our own private key (for computing ECDH shared secret)
    ///   - invoiceNumber: Any string identifying the purpose
    /// - Returns: The derived child public key, or nil on failure
    public static func derivePublicKey(
        publicKey: PublicKey,
        ownPrivateKey: PrivateKey,
        invoiceNumber: String
    ) -> PublicKey? {
        guard let sharedPoint = ecdhSharedSecret(privateKey: ownPrivateKey, publicKey: publicKey) else {
            return nil
        }

        let sharedSecret = Data(sharedPoint).sha256()

        guard let invoiceData = invoiceNumber.data(using: .utf8) else {
            return nil
        }
        let hmac = hmacSHA256(key: sharedSecret, data: invoiceData)

        // childPubKey = masterPubKey + hmac * G
        do {
            let pubkeyBytes = [UInt8](publicKey.toDer())
            let tweakedBytes = try Secp256k1.publicKeyTweakAdd(pubkeyBytes, tweak: [UInt8](hmac))
            guard let childKey = PublicKey(fromDer: Data(tweakedBytes)) else {
                return nil
            }
            return childKey
        } catch {
            return nil
        }
    }

    // MARK: - Self-Derivation (BRC-43)

    /// Derive a key using self-derivation (own public key as counterparty).
    /// Most common for wallet-internal keys.
    /// - Parameters:
    ///   - privateKey: The master private key
    ///   - invoiceNumber: BRC-43 format: "{securityLevel}-{protocol}-{keyId}"
    /// - Returns: The derived child private key
    public static func deriveSelf(
        privateKey: PrivateKey,
        invoiceNumber: String
    ) -> PrivateKey? {
        return derivePrivateKey(
            privateKey: privateKey,
            counterpartyPublicKey: privateKey.publicKey,
            invoiceNumber: invoiceNumber
        )
    }

    // MARK: - Convenience Methods

    /// Derive a child key and return both the key and address.
    public static func deriveAddress(
        privateKey: PrivateKey,
        counterpartyPublicKey: PublicKey,
        invoiceNumber: String
    ) -> (privateKey: PrivateKey, address: Address)? {
        guard let childKey = derivePrivateKey(
            privateKey: privateKey,
            counterpartyPublicKey: counterpartyPublicKey,
            invoiceNumber: invoiceNumber
        ) else {
            return nil
        }
        return (childKey, childKey.publicKey.address)
    }

    /// Derive a change address using Type42 self-derivation.
    /// Invoice format: "0-change-{index}"
    public static func deriveChangeKey(
        privateKey: PrivateKey,
        index: Int
    ) -> PrivateKey? {
        return deriveSelf(
            privateKey: privateKey,
            invoiceNumber: "0-change-\(index)"
        )
    }

    /// Derive a receiving address for a specific counterparty.
    /// Invoice format: "1-payment-{invoiceId}"
    public static func derivePaymentKey(
        privateKey: PrivateKey,
        counterpartyPublicKey: PublicKey,
        paymentId: String
    ) -> PrivateKey? {
        return derivePrivateKey(
            privateKey: privateKey,
            counterpartyPublicKey: counterpartyPublicKey,
            invoiceNumber: "1-payment-\(paymentId)"
        )
    }

    /// Derive an encryption key (BRC-43: security level 2).
    public static func deriveEncryptionKey(
        privateKey: PrivateKey,
        counterpartyPublicKey: PublicKey,
        keyId: String = "default"
    ) -> PrivateKey? {
        return derivePrivateKey(
            privateKey: privateKey,
            counterpartyPublicKey: counterpartyPublicKey,
            invoiceNumber: "2-encryption-\(keyId)"
        )
    }

    // MARK: - BAP Identity (BRC standard HD path)

    /// Derive BAP identity from a BIP32 root key using standard HD path.
    /// BAP root path: m/424150'/0'/0' (424150 = "BAP" as decimal)
    /// Signing keys at: m/424150'/0'/0'/signingPathIndex/0/0
    /// Reference: https://github.com/icellan/bap
    /// - Parameters:
    ///   - rootBip32: The wallet's master BIP32 key (from seed)
    ///   - identityIndex: Identity counter (default 0)
    ///   - signingPathIndex: Current signing key rotation index (default 0)
    /// - Returns: (rootKey, signingKey, bapId) or nil on failure
    public static func deriveBAPIdentity(
        rootBip32: Bip32,
        identityIndex: Int = 0,
        signingPathIndex: Int = 0
    ) -> (rootKey: Bip32, signingKey: PrivateKey, bapId: String)? {
        let bapBasePath = "m/424150'/\(identityIndex)'/0'"
        guard let bapBase = rootBip32.derivedKey(path: bapBasePath) else {
            return nil
        }

        guard let identityBip32 = bapBase.derivedKey(path: "0/0/0") else {
            return nil
        }

        let signingPath = "0/0/\(signingPathIndex + 1)"
        guard let signingBip32 = bapBase.derivedKey(path: signingPath),
              let signingKey = signingBip32.privateKey else {
            return nil
        }

        guard let rootPubKey = identityBip32.privateKey?.publicKey else { return nil }
        let rootAddress = rootPubKey.address.toString()
        let sha256Hash = Data(rootAddress.utf8).sha256()
        let hash160 = Crypto.ripemd160(sha256Hash)
        let bapId = hash160.hex

        return (identityBip32, signingKey, bapId)
    }

    // MARK: - Seed to Master Key

    /// Convert a BIP39 seed to a Type42 master private key.
    /// Uses the BIP32 master private key for interoperability with other BRC-42 wallets.
    public static func masterKeyFromSeed(_ seed: Data) -> PrivateKey? {
        let bip32 = Bip32(seed: seed)
        guard let masterKey = bip32.privateKey else {
            return nil
        }
        guard masterKey.bn > 0 && masterKey.bn < N else {
            return nil
        }
        return masterKey
    }

    // MARK: - ECDH

    /// Compute ECDH shared secret (point multiplication).
    /// Returns the full 33-byte compressed point (matches @bsv/sdk canonical BRC-42).
    ///
    /// Uses `publicKeyTweakMul` which performs `point * scalar` — the same elliptic curve
    /// scalar multiplication as ECDH.
    public static func ecdhSharedSecret(privateKey: PrivateKey, publicKey: PublicKey) -> [UInt8]? {
        do {
            let pubkeyBytes = [UInt8](publicKey.toDer())
            var keyScalar = padTo32Bytes(privateKey.data)
            let sharedPointBytes = try Secp256k1.publicKeyTweakMul(pubkeyBytes, tweak: keyScalar)
            for i in keyScalar.indices { keyScalar[i] = 0 }
            return Array(sharedPointBytes)
        } catch {
            return nil
        }
    }

    // MARK: - Helpers

    /// HMAC-SHA256 using CryptoSwift.
    public static func hmacSHA256(key: Data, data: Data) -> Data {
        do {
            let mac = try HMAC(key: [UInt8](key), variant: .sha2(.sha256)).authenticate([UInt8](data))
            return Data(mac)
        } catch {
            fatalError("HMAC-SHA256 failed: \(error.localizedDescription)")
        }
    }

    /// Ensure data is exactly 32 bytes (left-pad with zeros if needed).
    /// BInt.data may return fewer than 32 bytes for small values,
    /// but secp256k1 functions require exactly 32-byte scalars.
    static func padTo32Bytes(_ data: Data) -> [UInt8] {
        if data.count >= 32 {
            return [UInt8](data.suffix(32))
        }
        return [UInt8](repeating: 0, count: 32 - data.count) + [UInt8](data)
    }
}
