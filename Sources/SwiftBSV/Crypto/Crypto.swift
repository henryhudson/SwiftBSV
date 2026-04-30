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
        // HMAC over arbitrary keyed bytes is mathematically total — the
        // CryptoSwift call only `throws` to satisfy a generic protocol
        // surface. A trap here would indicate library corruption, not a
        // recoverable error, so we fail loudly rather than poison every
        // caller's signature with `throws`. (Bip32 derivation calls this
        // on every step; making it throw would cascade through the entire
        // HD-wallet API for no real-world benefit.)
        let output = try! HMAC(key: [UInt8](key), variant: .sha2(.sha512)).authenticate([UInt8](data))
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

    /// Sign a 32-byte message digest with the given private key, producing a
    /// DER-encoded signature suitable for embedding in a transaction
    /// scriptSig (after appending the sighash-type byte).
    ///
    /// Uses RFC-6979 deterministic nonces so the same input always yields
    /// the same signature — important for testability and for protocols
    /// that fingerprint signers via nonces.
    public static func sign(_ message: Data, privateKey: PrivateKey) -> Data {
        // Previously this function ran THREE signing operations
        // (Secp256k1.sign, ECDSA.signMessage, ECDSA.sign) and asserted
        // equality between two of them via `precondition`. The extra paths
        // were debug carry-over from porting the code and produced no
        // additional safety: a divergence between them would crash the
        // app in production with no recovery, while still leaving a
        // would-be-invalid signature in flight. Single canonical path now,
        // with RFC-6979 nonce explicitly named at the call site.
        let sig = try! Secp256k1.sign(
            msg: [UInt8](message),
            with: [UInt8](privateKey.data),
            nonceFunction: .rfc6979
        )
        return Data(sig)
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

        // `signatureHash` returns the digest in display (txid-style) byte order
        // — the moneybutton/bsv legacy convention this library mirrors.
        // libsecp256k1 verifies against the natural-order 32-byte digest, the
        // same bytes `Transaction.sign` hands to `Crypto.sign`. Without this
        // reversal `sign` and `verify` operated on byte-reversed twins of the
        // same digest, so locally-signed transactions would never validate
        // through OP_CHECKSIG (the network was the only verifier that worked).
        let sighashNatural = Data(sighash.reversed())
        return try ECDSA.verifySignature(signature, message: sighashNatural, publicKeyData: pubKeyData)
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

