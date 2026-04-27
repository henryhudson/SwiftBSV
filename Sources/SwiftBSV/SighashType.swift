//
//  SighashType.swift
//  HDWalletKit
//
//  Created by Pavlo Boiko on 1/7/19.
//  Copyright © 2019 Essentia. All rights reserved.
//

import Foundation

private let SIGHASH_ALL: UInt8 = 0x01 // 00000001
private let SIGHASH_NONE: UInt8 = 0x02 // 00000010
private let SIGHASH_SINGLE: UInt8 = 0x03 // 00000011
private let SIGHASH_CHRONICLE: UInt8 = 0x20 // 00100000 — Chronicle upgrade: use original tx digest
private let SIGHASH_FORK_ID: UInt8 = 0x40 // 01000000
private let SIGHASH_ANYONECANPAY: UInt8 = 0x80 // 10000000

private let SIGHASH_OUTPUT_MASK: UInt8 = 0x1f // 00011111

public enum SignatureVersion: Equatable, Sendable {
    case forkId
    case legacy
}

public enum SighashBase: UInt8, Equatable, Sendable {
    case unsupported = 0
    case all = 1
    case none = 2
    case single = 3

    var uint32: UInt32 {
        return UInt32(rawValue)
    }
}

public enum SighashFlags: UInt8, Equatable, Sendable {
    case SIGHASH_ALL = 1
    case SIGHASH_NONE = 2
    case SIGHASH_SINGLE = 3
    case SIGHASH_FORKID = 0x40
    case SIGHASH_ANYONECANPAY = 0x80
}

// Based on
// https://github.com/bitcoin-sv/bitcoin-sv/blob/d9b12a23dbf0d2afc5f488fa077d762b302ba873/src/script/sighashtype.h#L37

public struct SighashType: Sendable {
    public let sighash: UInt32

    public var baseType: SighashBase {
        let value = UInt8(sighash & UInt32(SIGHASH_OUTPUT_MASK))

        switch value {
        case 2:
            return .none
        case 3:
            return .single
        case 1:
            return .all
        default:
            return .all
        }
    }

    public var hasForkId: Bool {
        return (sighash & UInt32(SIGHASH_FORK_ID)) != 0
    }
    /// Chronicle upgrade: when set, use the original (pre-BIP143) transaction digest algorithm
    public var hasChronicle: Bool {
        return (sighash & UInt32(SIGHASH_CHRONICLE)) != 0
    }
    public var hasAnyoneCanPay: Bool {
        return (sighash & UInt32(SIGHASH_ANYONECANPAY)) != 0
    }

    public var isAll: Bool {
        return baseType == .all
    }
    public var isSingle: Bool {
        return baseType == .single
    }
    public var isNone: Bool {
        return baseType == .none
    }

    public init(i: Int) {
        sighash = UInt32(truncatingIfNeeded: i)
    }

    public init(ui8: UInt8) {
        sighash = UInt32(ui8)
    }

    public init(sighash: UInt32) {
        self.sighash = sighash
    }

    public func withBaseType(_ baseType: SighashBase) -> Self {
        return Self.init(sighash: (sighash & ~UInt32(SIGHASH_OUTPUT_MASK)) | UInt32(baseType.rawValue))
    }

    public func withForkValue(forkId: UInt32) -> Self {
        return Self.init(sighash: (forkId << 8) | (sighash & 0xff))
    }

    public func withForkId(hasForkId: Bool) -> Self {
        return Self.init(sighash: (sighash & ~UInt32(SIGHASH_FORK_ID)) | (hasForkId ? UInt32(SIGHASH_FORK_ID) : 0))
    }

    public func withAnyoneCanPay(anyoneCanPay: Bool) -> Self {
        return Self.init(sighash: (sighash & ~UInt32(SIGHASH_ANYONECANPAY)) | (anyoneCanPay ? UInt32(SIGHASH_ANYONECANPAY) : 0))
    }

    /// Chronicle upgrade: use the original transaction digest algorithm (OTDA)
    public func withChronicle(chronicle: Bool) -> Self {
        return Self.init(sighash: (sighash & ~UInt32(SIGHASH_CHRONICLE)) | (chronicle ? UInt32(SIGHASH_CHRONICLE) : 0))
    }

}

extension SighashType {
    public struct BSV {
        public static let ALL: SighashType = SighashType(ui8: SIGHASH_FORK_ID + SIGHASH_ALL) // 01000001
        public static let NONE: SighashType = SighashType(ui8: SIGHASH_FORK_ID + SIGHASH_NONE) // 01000010
        public static let SINGLE: SighashType = SighashType(ui8: SIGHASH_FORK_ID + SIGHASH_SINGLE) // 01000011
        public static let ALL_ANYONECANPAY: SighashType = SighashType(ui8: SIGHASH_FORK_ID + SIGHASH_ALL + SIGHASH_ANYONECANPAY) // 11000001
        public static let NONE_ANYONECANPAY: SighashType = SighashType(ui8: SIGHASH_FORK_ID + SIGHASH_NONE + SIGHASH_ANYONECANPAY) // 11000010
        public static let SINGLE_ANYONECANPAY: SighashType = SighashType(ui8: SIGHASH_FORK_ID + SIGHASH_SINGLE + SIGHASH_ANYONECANPAY) // 11000011
    }

    public struct BTC {
        public static let ALL: SighashType = SighashType(ui8: SIGHASH_ALL) // 00000001
        public static let NONE: SighashType = SighashType(ui8: SIGHASH_NONE) // 00000010
        public static let SINGLE: SighashType = SighashType(ui8: SIGHASH_SINGLE) // 00000011
        public static let ALL_ANYONECANPAY: SighashType = SighashType(ui8: SIGHASH_ALL + SIGHASH_ANYONECANPAY) // 10000001
        public static let NONE_ANYONECANPAY: SighashType = SighashType(ui8: SIGHASH_NONE + SIGHASH_ANYONECANPAY) // 10000010
        public static let SINGLE_ANYONECANPAY: SighashType = SighashType(ui8: SIGHASH_SINGLE + SIGHASH_ANYONECANPAY) // 10000011
    }
}
