//
//  ECIES.swift
//  SwiftBSV
//
//  BRC-2 / Electrum ECIES encryption using ECDH key agreement + AES-CBC + HMAC-SHA256.
//  Wire-compatible with @bsv/sdk EncryptedMessage and other BSV wallets.
//
//  Wire format: "BIE1" (4 bytes) || sender_pubkey (33 bytes) || AES-CBC ciphertext || HMAC-SHA256 (32 bytes)
//  Key derivation: SHA-512(compressed_encoding_of_shared_point, 33 bytes) → iv[0:16], kE[16:32], kM[32:64]
//  HMAC input: BIE1 || sender_pubkey || ciphertext (NOT just ciphertext — the MAC must cover the whole transmitted payload).
//
//  Reference: BRC-2 specification
//

import Foundation
import CryptoSwift

/// Errors that can occur during BRC-2 ECIES encryption/decryption.
public enum ECIESError: Error, LocalizedError {
    case ecdhFailed
    case encryptionFailed
    case decryptionFailed
    case invalidCiphertext
    case invalidPublicKey
    case hmacVerificationFailed

    public var errorDescription: String? {
        switch self {
        case .ecdhFailed: return "ECDH shared secret computation failed"
        case .encryptionFailed: return "AES-CBC encryption failed"
        case .decryptionFailed: return "AES-CBC decryption failed"
        case .invalidCiphertext: return "Invalid BRC-2 ciphertext format"
        case .invalidPublicKey: return "Invalid public key"
        case .hmacVerificationFailed: return "HMAC verification failed — ciphertext was tampered with"
        }
    }
}

/// BRC-2 / Electrum ECIES encryption.
///
/// Provides encrypt/decrypt using ECDH + AES-128-CBC + HMAC-SHA256,
/// wire-compatible with `@bsv/sdk` `EncryptedMessage`.
public struct ECIESEncryption {

    /// BRC-2 wire format magic bytes: "BIE1"
    private static let magic = Data([0x42, 0x49, 0x45, 0x31])

    // MARK: - Encrypt

    /// Encrypt data using BRC-2 (Electrum ECIES) format.
    /// Wire format: "BIE1" || sender_compressed_pubkey (33) || AES-CBC ciphertext || HMAC-SHA256 (32)
    public static func encrypt(
        plaintext: Data,
        senderPrivateKey: PrivateKey,
        recipientPublicKey: PublicKey
    ) throws -> Data {
        // 1. ECDH: compute shared point (returned as 33-byte compressed encoding)
        let sharedPoint = try computeECDH(privateKey: senderPrivateKey, publicKey: recipientPublicKey)

        // 2. SHA-512 key derivation over the full 33-byte compressed
        // encoding of the shared point — not just the X coordinate. The
        // prefix byte encodes Y's parity, which is public information
        // once X is known, so including it leaks nothing; @bsv/sdk's
        // electrumEncrypt and the canonical Electrum implementation do
        // the same. SwiftBSV previously hashed only the 32-byte X here,
        // which produced different (incompatible) IV/kE/kM and silently
        // broke wire interop despite the file header's claim.
        let hash = sharedPoint.sha512()
        let iv = Array(hash[0..<16])      // 16 bytes: AES IV
        let kE = Array(hash[16..<32])     // 16 bytes: AES key
        let kM = Array(hash[32..<64])     // 32 bytes: HMAC key

        // 4. AES-CBC encrypt with PKCS7 padding
        let ciphertext: [UInt8]
        do {
            let aes = try AES(key: kE, blockMode: CBC(iv: iv), padding: .pkcs7)
            ciphertext = try aes.encrypt([UInt8](plaintext))
        } catch {
            throw ECIESError.encryptionFailed
        }

        // 5. HMAC-SHA256 over `magic || sender_pubkey || ciphertext`.
        // The MAC must cover the full payload that's transmitted; HMACing
        // only the AES ciphertext silently allows an attacker to swap in
        // a different sender pubkey while the HMAC still validates. This
        // is also the wire shape the BRC-2 spec and @bsv/sdk's
        // electrumEncrypt produce, so an HMAC over just the ciphertext
        // would never decrypt their messages (and vice versa) — i.e. it
        // wasn't actually wire-compatible with @bsv/sdk despite the file
        // header's claim. Fixed cross-implementation interop test surfaces
        // this; see Henceforth's BRC100Interop_Tests for vectors.
        let senderPubData = senderPrivateKey.publicKey.toDer()
        var macInput = [UInt8]()
        macInput.append(contentsOf: [UInt8](magic))
        macInput.append(contentsOf: [UInt8](senderPubData))
        macInput.append(contentsOf: ciphertext)

        let hmac: [UInt8]
        do {
            hmac = try HMAC(key: kM, variant: .sha2(.sha256)).authenticate(macInput)
        } catch {
            throw ECIESError.encryptionFailed
        }

        // 6. Assemble: magic + sender pubkey + ciphertext + hmac
        var result = Data(capacity: 4 + 33 + ciphertext.count + 32)
        result.append(magic)                    // 4 bytes
        result.append(senderPubData)            // 33 bytes (compressed)
        result.append(Data(ciphertext))         // variable
        result.append(Data(hmac))               // 32 bytes
        return result
    }

    // MARK: - Decrypt

    /// Decrypt a BRC-2 (Electrum ECIES) message.
    public static func decrypt(
        ciphertext: Data,
        recipientPrivateKey: PrivateKey
    ) throws -> Data {
        // Minimum: 4 (magic) + 33 (pubkey) + 16 (min AES block) + 32 (hmac) = 85
        guard ciphertext.count >= 85 else {
            throw ECIESError.invalidCiphertext
        }

        // 1. Verify magic
        guard ciphertext[0..<4] == magic else {
            throw ECIESError.invalidCiphertext
        }

        // 2. Extract sender's public key.
        // `Data(...)` materializes a zero-indexed copy — without it, `ciphertext`
        // slicing preserves parent indices and `PublicKey(fromDer:)` would crash
        // on `buffer[0]`. PublicKey now defends against this internally too, but
        // making it explicit at the call-site documents the wire-format extraction.
        let senderPubData = Data(ciphertext[4..<37])
        guard let senderPublicKey = PublicKey(fromDer: senderPubData) else {
            throw ECIESError.invalidPublicKey
        }

        // 3. Split ciphertext and HMAC
        let encryptedData = [UInt8](ciphertext[37..<(ciphertext.count - 32)])
        let receivedHMAC = [UInt8](ciphertext[(ciphertext.count - 32)...])

        // 4. ECDH (returned as 33-byte compressed encoding)
        let sharedPoint = try computeECDH(privateKey: recipientPrivateKey, publicKey: senderPublicKey)

        // 5. Key derivation: SHA-512 over the full compressed point.
        // See the matching encrypt-path comment for the rationale —
        // both sides must hash the same input or the IV/kE/kM differ.
        let hash = sharedPoint.sha512()
        let iv = Array(hash[0..<16])
        let kE = Array(hash[16..<32])
        let kM = Array(hash[32..<64])

        // 6. Verify HMAC before decryption (authenticate-then-decrypt).
        // The MAC covers `magic || sender_pubkey || ciphertext` (per BRC-2
        // and @bsv/sdk electrumDecrypt), NOT just the ciphertext —
        // recompute over the same bytes the sender authenticated. Use a
        // constant-time comparison so a Bleichenbacher-style timing probe
        // cannot recover the HMAC byte-by-byte by measuring how long the
        // reject takes. Plain `==` on `[UInt8]` short-circuits on the
        // first mismatching byte and leaks prefix-match length.
        var macInput = [UInt8]()
        macInput.append(contentsOf: [UInt8](magic))
        macInput.append(contentsOf: [UInt8](senderPubData))
        macInput.append(contentsOf: encryptedData)
        let expectedHMAC: [UInt8]
        do {
            expectedHMAC = try HMAC(key: kM, variant: .sha2(.sha256)).authenticate(macInput)
        } catch {
            throw ECIESError.hmacVerificationFailed
        }
        guard ECIESEncryption.constantTimeEquals(expectedHMAC, receivedHMAC) else {
            throw ECIESError.hmacVerificationFailed
        }

        // 7. AES-CBC decrypt
        do {
            let aes = try AES(key: kE, blockMode: CBC(iv: iv), padding: .pkcs7)
            let plaintext = try aes.decrypt(encryptedData)
            return Data(plaintext)
        } catch {
            throw ECIESError.decryptionFailed
        }
    }

    // MARK: - Constant-Time Comparison

    /// Constant-time byte-array equality. Iterates the full length of both
    /// inputs (XOR-OR-accumulate) so the wall-clock cost cannot be used to
    /// infer how many leading bytes match. Used for HMAC verification —
    /// `==` on `[UInt8]` short-circuits on the first mismatching byte and
    /// leaks prefix-match length, which a Bleichenbacher-style probe
    /// could exploit to recover the HMAC byte-by-byte over many attempts.
    static func constantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<lhs.count {
            diff |= lhs[i] ^ rhs[i]
        }
        return diff == 0
    }

    // MARK: - String Convenience

    /// Encrypt a UTF-8 string message.
    public static func encrypt(
        message: String,
        senderPrivateKey: PrivateKey,
        recipientPublicKey: PublicKey
    ) throws -> Data {
        guard let data = message.data(using: .utf8) else {
            throw ECIESError.encryptionFailed
        }
        return try encrypt(plaintext: data, senderPrivateKey: senderPrivateKey, recipientPublicKey: recipientPublicKey)
    }

    /// Decrypt to a UTF-8 string.
    public static func decryptToString(
        ciphertext: Data,
        recipientPrivateKey: PrivateKey
    ) throws -> String {
        let data = try decrypt(ciphertext: ciphertext, recipientPrivateKey: recipientPrivateKey)
        guard let string = String(data: data, encoding: .utf8) else {
            throw ECIESError.decryptionFailed
        }
        return string
    }

    /// Encrypt a UTF-8 string (alternate label matching app convention).
    public static func encryptString(
        _ message: String,
        senderPrivateKey: PrivateKey,
        recipientPublicKey: PublicKey
    ) throws -> Data {
        try encrypt(message: message, senderPrivateKey: senderPrivateKey, recipientPublicKey: recipientPublicKey)
    }

    /// Decrypt to a UTF-8 string (alternate label matching app convention).
    public static func decryptString(
        _ ciphertext: Data,
        recipientPrivateKey: PrivateKey
    ) throws -> String {
        try decryptToString(ciphertext: ciphertext, recipientPrivateKey: recipientPrivateKey)
    }

    // MARK: - ECDH

    /// Compute ECDH shared point via secp256k1 point multiplication.
    /// Returns compressed public key (33 bytes); x-coordinate is bytes[1:33].
    private static func computeECDH(privateKey: PrivateKey, publicKey: PublicKey) throws -> [UInt8] {
        let pubBytes = [UInt8](publicKey.toDer())
        var keyBytes = Type42.padTo32Bytes(privateKey.data)

        do {
            let result = try Secp256k1.publicKeyTweakMul(pubBytes, tweak: keyBytes)
            for i in keyBytes.indices { keyBytes[i] = 0 }
            return result
        } catch {
            for i in keyBytes.indices { keyBytes[i] = 0 }
            throw ECIESError.ecdhFailed
        }
    }
}
