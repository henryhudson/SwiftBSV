//
//  Crypto.swift
//  Swift BSV
//
//  Created by yuzushioh on 2018/02/06.
//  Modifications by Will Townsend from 2020/10/19
//
//  Copyright © 2018 yuzushioh. All rights reserved.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation
import CryptoSwift
import secp256k1

public final class Crypto {

    public static func ripemd160(_ data: Data) -> Data {
        return RIPEMD160.hash(data)
    }

    public static func sha256ripemd160(_ data: Data) -> Data {
        return ripemd160(data.sha256())
    }

    public static func sha1(_ data: Data) -> Data {
        return data.sha1()
    }

    public static func sha256(_ data: Data) -> Data {
        return data.sha256()
    }

    public static func sha256sha256(_ data: Data) -> Data {
        return sha256(sha256(data))
    }

   public static func hmacsha512(key: Data, data: Data) -> Data {
        let output: [UInt8]
        do {
            // CryptoSwift deprecated `.sha512` in favour of `.sha2(.sha512)`
            // (with the addition of more SHA-2 variants in `.sha2(_:)`).
            output = try HMAC(key: [UInt8](key), variant: .sha2(.sha512)).authenticate([UInt8](data))
        } catch let error {
            fatalError("Error occured. Description: \(error.localizedDescription)")
        }
        return Data(output)
    }

//    public static func PBKDF2SHA512(password: [UInt8], salt: [UInt8]) -> Data {
//        let output: [UInt8]
//        do {
//            output = try PKCS5.PBKDF2(password: password, salt: salt, iterations: 2048, variant: .sha512).calculate()
//        } catch let error {
//            fatalError("PKCS5.PBKDF2 faild: \(error.localizedDescription)")
//        }
//        return Data(output)
//    }

    public static func sha3keccak256(data:Data) -> Data {
        return Data(SHA3(variant: .keccak256).calculate(for: [UInt8](data)))
    }
//
//    public static func hashSHA3_256(_ data: Data) -> Data {
//        return Data(CryptoSwift.SHA3(variant: .sha256).calculate(for: data.bytes))
//    }

    public static func sign(_ message: Data, privateKey: PrivateKey) -> Data {

        let sig_ = try! Secp256k1.sign(msg: [UInt8](message), with: [UInt8](privateKey.data), nonceFunction: Secp256k1.NonceFunction.rfc6979)
        let sig = Data(sig_)

        let a = try! ECDSA.signMessage(message, withPrivateKey: privateKey.data)
        // ECDSA.sign smoke-checks the alternative path runs without crashing.
        // Result is intentionally discarded — we only enforce equality between
        // Secp256k1.sign (DER) and ECDSA.signMessage via the precondition below.
        _ = ECDSA.sign(message, privateKey: privateKey.data)

        precondition(a == sig)

        return sig
    }

    public static func signCompact(_ message: Data, privateKey: PrivateKey) -> (sig: Data, recoveryId: Int32) {
        let compact = try! Secp256k1.signCompact(msg: [UInt8](message), with: [UInt8](privateKey.data), nonceFunction: Secp256k1.NonceFunction.rfc6979)

        return (sig: Data(compact.sig), recoveryId: compact.recID)
    }

    public static func verifySignature(_ signature: Data, message: Data, publicKey: PublicKey) -> Bool {
        let publicKey = publicKey.toDer()

        return try! ECDSA.verifySignature(signature, message: message, publicKeyData: publicKey)
    }

    public static func verifySignatureCompact(_ signature: Data, message: Data, publicKeyData: Data) -> Bool {

        return try! ECDSA.verifySignatureCompact(signature, message: message, publicKeyData: publicKeyData)
    }

    /// Verify a Bitcoin transaction signature against a UTXO's locking script.
    ///
    /// `sigData` is the wire-format signature: a DER-encoded ECDSA signature
    /// followed by a single sighash-type byte (e.g. `0x41` for SIGHASH_ALL |
    /// SIGHASH_FORKID, the BSV standard). The function strips the trailing
    /// sighash byte, computes the message digest the signer would have
    /// produced, and verifies the DER signature against that digest with
    /// the supplied compressed/uncompressed public key.
    ///
    /// Used from `OP_CHECKSIG` and `OP_CHECKMULTISIG`. Previously this method
    /// crashed with `fatalError("TODO")` — any script execution path that
    /// hit those opcodes would terminate the process. Now implemented via
    /// the `TransactionInputSigner.signatureHash` digest and
    /// `ECDSA.verifySignature` (DER) primitives.
    public static func verifySigData(
        for tx: Transaction,
        inputIndex: Int,
        utxo: TransactionOutput,
        sigData: Data,
        pubKeyData: Data
    ) throws -> Bool {
        guard let sighashByte = sigData.last else {
            throw OpCodeExecutionError.error("SigData is empty — cannot verify signature.")
        }
        let sighashType = SighashType(ui8: sighashByte)
        // BSV transactions use SIGHASH_FORKID (BIP143) by default;
        // legacy pre-fork digests are still supported for replaying
        // historic transactions or running the scripted-test vectors.
        let signatureVersion: SignatureVersion = sighashType.hasForkId ? .forkId : .legacy

        // Strip the trailing sighash-type byte to recover the pure DER signature.
        let signature = Data(sigData.dropLast())

        // For non-segwit P2PKH (the BSV standard locking pattern) the
        // subScript is the UTXO's locking script. A more general impl
        // would honour OP_CODESEPARATOR scoping, but every BSV-standard
        // script template is OP_CODESEPARATOR-free.
        let subScript = Script(data: utxo.lockingScript) ?? Script()

        let sighash = TransactionInputSigner.signatureHash(
            tx: tx,
            signatureVersion: signatureVersion,
            sighashType: sighashType,
            nIn: inputIndex,
            subScript: subScript,
            value: utxo.value
        )

        return try ECDSA.verifySignature(signature, message: sighash, publicKeyData: pubKeyData)
    }

    public static func computePublicKey(fromPrivateKey privateKey: Data, compressed: Bool) -> Data {
        guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)) else {
            return Data()
        }
        defer { secp256k1_context_destroy(ctx) }
        var pubkey = secp256k1_pubkey()
        var seckey: [UInt8] = privateKey.map { $0 }
        if seckey.count != 32 {
            return Data()
        }
        if secp256k1_ec_pubkey_create(ctx, &pubkey, &seckey) == 0 {
            return Data()
        }
        if compressed {
            var serializedPubkey = [UInt8](repeating: 0, count: 33)
            var outputlen = 33
            if secp256k1_ec_pubkey_serialize(ctx, &serializedPubkey, &outputlen, &pubkey, UInt32(SECP256K1_EC_COMPRESSED)) == 0 {
                return Data()
            }
            if outputlen != 33 {
                return Data()
            }
            return Data(serializedPubkey)
        } else {
            var serializedPubkey = [UInt8](repeating: 0, count: 65)
            var outputlen = 65
            if secp256k1_ec_pubkey_serialize(ctx, &serializedPubkey, &outputlen, &pubkey, UInt32(SECP256K1_EC_UNCOMPRESSED)) == 0 {
                return Data()
            }
            if outputlen != 65 {
                return Data()
            }
            return Data(serializedPubkey)
        }
    }

    /// Serialize a publicKey
    ///
    /// Useful to convert a compressed pubKey into an uncompressed pubKey
    public static func serializePublicKey(from publicKey: Data, compressed: Bool = true) -> Data {
        guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY)) else {
            return Data()
        }
        defer { secp256k1_context_destroy(ctx) }
        var pubkey = secp256k1_pubkey()
        var input: [UInt8] = publicKey.map { $0 }

        if secp256k1_ec_pubkey_parse(ctx, &pubkey, &input, input.count) == 0 {
            return Data()
        }

        if compressed {
            var serializedPubkey = [UInt8](repeating: 0, count: 33)
            var outputlen = 33
            if secp256k1_ec_pubkey_serialize(ctx, &serializedPubkey, &outputlen, &pubkey, UInt32(SECP256K1_EC_COMPRESSED)) == 0 {
                return Data()
            }
            if outputlen != 33 {
                return Data()
            }
            return Data(serializedPubkey)
        } else {
            var serializedPubkey = [UInt8](repeating: 0, count: 65)
            var outputlen = 65
            if secp256k1_ec_pubkey_serialize(ctx, &serializedPubkey, &outputlen, &pubkey, UInt32(SECP256K1_EC_UNCOMPRESSED)) == 0 {
                return Data()
            }
            if outputlen != 65 {
                return Data()
            }
            return Data(serializedPubkey)
        }
    }

}

