//
//  PrivateKey.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-17.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation

public struct PrivateKey: Sendable {

    /// The BInt of the private key
    public let bn: BInt

    /// Whether the PrivateKey was inialized from a compressed source.
    private let isCompressed: Bool

    /// The Bitcoin Network this PrivateKey belongs to.
    public let network: Network

    /// The raw 32-byte private key.
    ///
    /// `BInt.data` is variable-width: a scalar like `0x0000...01` (with leading
    /// zero bytes) returns fewer than 32 bytes. libsecp256k1 requires exactly
    /// 32-byte scalars and ECDSA.sign asserts on the precondition, so we
    /// left-pad here. Skipping this fix would crash on roughly 1-in-256
    /// derived keys (per leading zero byte).
    public var data: Data {
        let raw = bn.data
        if raw.count >= 32 { return raw.suffix(32) }
        var padded = Data(repeating: 0, count: 32 - raw.count)
        padded.append(raw)
        return padded
    }

    /// Return the associated Public Key.
    /// Crashes only if libsecp256k1 fails to derive — i.e. a corrupted
    /// PrivateKey value crossed the validation gates above. Practically
    /// unreachable because every constructor rejects out-of-range scalars.
    public var publicKey: PublicKey {
        let publicKeyData = Crypto.computePublicKey(fromPrivateKey: data, compressed: true)
        guard let key = PublicKey(fromDer: publicKeyData) else {
            fatalError("PrivateKey.publicKey: secp256k1 derivation failed for a previously-validated scalar — this should be unreachable")
        }
        return key
    }

    public var address: Address {
        return Address(self, network: network)
    }

    public init(network: Network = .mainnet) {
        var buffer: Data
        var number: BInt
        var condition: Bool
        repeat {
            buffer = Data.randomBytes(length: 32)
            number = BInt(data: buffer)
            // Reject 0 as well as values >= N. A zero scalar is an invalid
            // private key (its public key is the identity point, signing
            // with it leaks the signer's identity, etc.); previously the
            // generator accepted it with probability 2^-256 per draw.
            condition = (number > 0) && (number < Point.N)
        } while (!condition)

        self.bn = number
        self.isCompressed = true
        self.network = network
    }

    public init(data: Data, network: Network = .mainnet) {
        let number = BInt(data: data)
        self.init(bn: number, network: network)
    }

    public init(bn: BInt, isCompressed: Bool = true, network: Network = .mainnet) {
        self.bn = bn
        self.network = network
        self.isCompressed = isCompressed
    }

    /// Failable buffer-form initializer. Returns nil on:
    /// - Wrong length (must be 33 uncompressed or 34 compressed)
    /// - Wrong version byte for the requested network
    ///
    /// Previously this fatalError'd, which meant a corrupted QR scan
    /// crashed the app instead of surfacing a recoverable error to the UI.
    public init?(buffer: Data, network: Network = .mainnet) {
        // Materialize a zero-indexed copy so the integer subscripts below
        // (`buffer[0]`, `buffer[33]`, `buffer[1..<33]`) are safe regardless
        // of whether the caller passed a `Data` slice.
        let buffer = Data(buffer)
        if buffer.count == 1 + 32 + 1 && buffer[1 + 32 + 1 - 1] == 1 {
            isCompressed = true
        } else if buffer.count == 1 + 32 {
            isCompressed = false
        } else {
            return nil
        }

        if buffer[0] != network.privateKeyVersionByteNum {
            return nil
        }

        let data = buffer[1..<33]
        let bn = BInt(data: data)

        self.bn = bn
        self.network = network
    }

    public init?(wif: String, network: Network = .mainnet) {
        guard let data = Base58Check.decode(wif) else {
            return nil
        }
        // `init?(buffer:)` is now failable, so propagate nil cleanly
        // instead of crashing on bad WIF.
        self.init(buffer: data, network: network)
    }

    /// Return the Wif encoded string
    public func toWif() -> String {
        Base58Check.encode(toWifData())
    }

    /// Return the Wif encoded data
    func toWifData() -> Data {
        var data = Data()
        data += network.privateKeyVersionByteNum

        if isCompressed {
            data += self.bn.data
            data += UInt8(0x01)
        } else {
            data += self.bn.data
        }

        return data
    }

}
