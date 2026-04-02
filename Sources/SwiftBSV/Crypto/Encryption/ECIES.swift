//
//  ECIES.swift
//  SwiftBSV
//
//  BRC-2 / Electrum ECIES encryption using ECDH key agreement + AES-CBC + HMAC-SHA256.
//  Wire-compatible with @bsv/sdk EncryptedMessage and other BSV wallets.
//
//  Wire format: "BIE1" (4 bytes) || sender_pubkey (33 bytes) || AES-CBC ciphertext || HMAC-SHA256 (32 bytes)
//  Key derivation: SHA-512(ECDH_shared_point.x) → iv[0:16], kE[16:32], kM[32:64]
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
        // 1. ECDH: compute shared point
        let sharedPoint = try computeECDH(privateKey: senderPrivateKey, publicKey: recipientPublicKey)

        // 2. Extract x-coordinate (skip 0x02/0x03 prefix byte)
        let xCoordinate = [UInt8](sharedPoint[1..<33])

        // 3. SHA-512 key derivation
        let hash = xCoordinate.sha512()
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

        // 5. HMAC-SHA256 over ciphertext
        let hmac: [UInt8]
        do {
            hmac = try HMAC(key: kM, variant: .sha2(.sha256)).authenticate(ciphertext)
        } catch {
            throw ECIESError.encryptionFailed
        }

        // 6. Assemble: magic + sender pubkey + ciphertext + hmac
        let senderPubData = senderPrivateKey.publicKey.toDer()
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

        // 2. Extract sender's public key
        let senderPubData = ciphertext[4..<37]
        guard let senderPublicKey = PublicKey(fromDer: senderPubData) else {
            throw ECIESError.invalidPublicKey
        }

        // 3. Split ciphertext and HMAC
        let encryptedData = [UInt8](ciphertext[37..<(ciphertext.count - 32)])
        let receivedHMAC = [UInt8](ciphertext[(ciphertext.count - 32)...])

        // 4. ECDH
        let sharedPoint = try computeECDH(privateKey: recipientPrivateKey, publicKey: senderPublicKey)

        // 5. Key derivation
        let xCoordinate = [UInt8](sharedPoint[1..<33])
        let hash = xCoordinate.sha512()
        let iv = Array(hash[0..<16])
        let kE = Array(hash[16..<32])
        let kM = Array(hash[32..<64])

        // 6. Verify HMAC before decryption (authenticate-then-decrypt)
        let expectedHMAC: [UInt8]
        do {
            expectedHMAC = try HMAC(key: kM, variant: .sha2(.sha256)).authenticate(encryptedData)
        } catch {
            throw ECIESError.hmacVerificationFailed
        }
        guard expectedHMAC == receivedHMAC else {
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
