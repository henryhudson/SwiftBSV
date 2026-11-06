//
//  BEEF.swift
//  SwiftBSV
//
//  BRC-62: Background Evaluation Extended Format (BEEF).
//  Bundles transactions with their Merkle proofs for offline SPV verification.
//  Includes parser, serializer, and builder.
//

import Foundation

// MARK: - BEEF Structures

/// A transaction within a BEEF structure
///
/// Sendable: `let`-only stored properties of `Sendable` types (Data,
/// Bool, UInt64?). Required so receivers can pass parsed BEEF
/// transactions across actor boundaries — e.g. from the MainActor
/// `internalizeAction` to the SPVService actor for BUMP caching.
public struct BEEFTransaction: Sendable {
    public let rawTx: Data
    public let hasBUMP: Bool
    public let bumpIndex: UInt64?
    /// Set only for a BEEF version 2 "txid only" entry: the transaction is
    /// named, not included, and `rawTx` is empty. Display (big-endian) hex.
    public let txidOnly: String?

    public init(rawTx: Data, hasBUMP: Bool, bumpIndex: UInt64?, txidOnly: String? = nil) {
        self.rawTx = rawTx
        self.hasBUMP = hasBUMP
        self.bumpIndex = bumpIndex
        self.txidOnly = txidOnly
    }
}

/// Background Evaluation Extended Format (BRC-62).
/// Bundles transactions with their Merkle proofs for offline SPV verification.
public struct BEEF: Sendable {
    /// BRC-62 version 1, 4022206465. On the wire, little-endian, it reads
    /// as the hex "0100beef", which is what @bsv/sdk writes. (This was
    /// 0x0100BEEF before, which put "efbe0001" on the wire: no other
    /// wallet writes or reads that.)
    public static let versionMarker: UInt32 = 0xEFBE_0001
    /// BRC-96 version 2, "0200beef" on the wire: each transaction carries a
    /// format byte and may be named by txid alone. @bsv/sdk's default.
    public static let versionMarkerV2: UInt32 = 0xEFBE_0002
    /// BRC-95 Atomic BEEF prefix, "01010101" on the wire, followed by the
    /// subject txid and a BEEF.
    public static let atomicPrefix: UInt32 = 0x0101_0101

    public let version: UInt32
    public let bumps: [BUMP]
    public let transactions: [BEEFTransaction]

    public init(version: UInt32 = versionMarker, bumps: [BUMP], transactions: [BEEFTransaction]) {
        self.version = version
        self.bumps = bumps
        self.transactions = transactions
    }
}

// MARK: - BEEF Parser

public enum BEEFParser {

    public enum ParseError: Error, LocalizedError {
        case invalidVersion(UInt32)
        case invalidData
        case unexpectedEnd

        public var errorDescription: String? {
            switch self {
            case .invalidVersion(let v): return "Invalid BEEF version: 0x\(String(v, radix: 16))"
            case .invalidData: return "Invalid BEEF data"
            case .unexpectedEnd: return "Unexpected end of BEEF data"
            }
        }
    }

    /// Parse a BEEF from hex string
    public static func parse(hex: String) throws -> BEEF {
        let data = Data(hex: hex)
        guard data.count >= 4 else { throw ParseError.invalidData }
        return try parse(data: data)
    }

    /// Parse a BEEF from raw bytes
    public static func parse(data: Data) throws -> BEEF {
        var offset = 0

        guard offset + 4 <= data.count else { throw ParseError.unexpectedEnd }
        let version = UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
        offset += 4

        guard version == BEEF.versionMarker || version == BEEF.versionMarkerV2 else {
            throw ParseError.invalidVersion(version)
        }
        let isV2 = version == BEEF.versionMarkerV2

        let nBumps = try BUMPParser.readVarInt(data: data, offset: &offset)
        var bumps: [BUMP] = []
        for _ in 0..<nBumps {
            let bump = try parseBUMPInline(data: data, offset: &offset)
            bumps.append(bump)
        }

        let nTxs = try BUMPParser.readVarInt(data: data, offset: &offset)
        var transactions: [BEEFTransaction] = []
        for _ in 0..<nTxs {
            if isV2 {
                // Format byte: 0 raw transaction, 1 raw transaction and a
                // BUMP index, 2 txid only.
                let format = try BUMPParser.readByte(data: data, offset: &offset)
                switch format {
                case 0, 1:
                    // Version 2 puts the BUMP index before the transaction.
                    let bumpIndex: UInt64? = format == 1
                        ? try BUMPParser.readVarInt(data: data, offset: &offset) : nil
                    let txStart = offset
                    try skipRawTransaction(data: data, offset: &offset)
                    let rawTx = Data(data[txStart..<offset])
                    transactions.append(BEEFTransaction(rawTx: rawTx, hasBUMP: format == 1, bumpIndex: bumpIndex))
                case 2:
                    let txid = try BUMPParser.readBytes(data: data, offset: &offset, count: 32)
                    transactions.append(BEEFTransaction(
                        rawTx: Data(), hasBUMP: false, bumpIndex: nil,
                        txidOnly: Data(txid.reversed()).hex))
                default:
                    throw ParseError.invalidData
                }
                continue
            }
            let txStart = offset
            // Propagate truncation as ParseError instead of silently leaving
            // `offset` partway through a malformed transaction. Previously
            // a truncated tx left `rawTx` as a half-parsed byte slice that
            // looked structurally valid but was broken downstream — exactly
            // the kind of error you want loud at parse time.
            try skipRawTransaction(data: data, offset: &offset)
            let rawTx = Data(data[txStart..<offset])

            guard offset < data.count else { throw ParseError.unexpectedEnd }
            let hasBUMPByte = data[offset]
            offset += 1

            var bumpIndex: UInt64?
            if hasBUMPByte == 0x01 {
                bumpIndex = try BUMPParser.readVarInt(data: data, offset: &offset)
            }

            transactions.append(BEEFTransaction(
                rawTx: rawTx,
                hasBUMP: hasBUMPByte == 0x01,
                bumpIndex: bumpIndex
            ))
        }

        return BEEF(version: version, bumps: bumps, transactions: transactions)
    }

    /// Parse BRC-95 Atomic BEEF: the prefix, the subject txid, then a
    /// BEEF whose last transaction must be the subject. Returns the subject
    /// txid in display (big-endian) hex with the BEEF.
    public static func parseAtomic(data: Data) throws -> (subjectTxid: String, beef: BEEF) {
        var offset = 0
        guard data.count >= 36 else { throw ParseError.unexpectedEnd }
        let prefix = UInt32(data[data.startIndex])
            | (UInt32(data[data.startIndex + 1]) << 8)
            | (UInt32(data[data.startIndex + 2]) << 16)
            | (UInt32(data[data.startIndex + 3]) << 24)
        guard prefix == BEEF.atomicPrefix else { throw ParseError.invalidVersion(prefix) }
        offset = 4
        let subject = try BUMPParser.readBytes(data: Data(data), offset: &offset, count: 32)
        let subjectTxid = Data(subject.reversed()).hex
        let beef = try parse(data: Data(data.dropFirst(36)))
        guard let last = beef.transactions.last, !last.rawTx.isEmpty,
              Data(Crypto.sha256sha256(last.rawTx).reversed()).hex == subjectTxid else {
            throw ParseError.invalidData
        }
        return (subjectTxid, beef)
    }

    /// Serialize a BEEF to binary
    public static func serialize(_ beef: BEEF) -> Data {
        var data = Data()

        let v = beef.version
        data.append(UInt8(v & 0xFF))
        data.append(UInt8((v >> 8) & 0xFF))
        data.append(UInt8((v >> 16) & 0xFF))
        data.append(UInt8((v >> 24) & 0xFF))

        BUMPParser.writeVarInt(UInt64(beef.bumps.count), to: &data)
        for bump in beef.bumps {
            data.append(BUMPParser.serialize(bump))
        }

        BUMPParser.writeVarInt(UInt64(beef.transactions.count), to: &data)
        let isV2 = beef.version == BEEF.versionMarkerV2
        for tx in beef.transactions {
            if isV2 {
                if let txid = tx.txidOnly {
                    data.append(2)
                    data.append(Data(Data(hex: txid).reversed()))
                } else {
                    if tx.hasBUMP, let idx = tx.bumpIndex {
                        data.append(1)
                        BUMPParser.writeVarInt(idx, to: &data)
                    } else {
                        data.append(0)
                    }
                    data.append(tx.rawTx)
                }
                continue
            }
            data.append(tx.rawTx)
            data.append(tx.hasBUMP ? 0x01 : 0x00)
            if tx.hasBUMP, let idx = tx.bumpIndex {
                BUMPParser.writeVarInt(idx, to: &data)
            }
        }

        return data
    }

    /// Serialize BEEF to hex string
    public static func serializeHex(_ beef: BEEF) -> String {
        serialize(beef).hex
    }

    // MARK: - Private Helpers

    private static func parseBUMPInline(data: Data, offset: inout Int) throws -> BUMP {
        let blockHeight = try BUMPParser.readVarInt(data: data, offset: &offset)
        let treeHeight = try BUMPParser.readByte(data: data, offset: &offset)

        var levels: [BUMPLevel] = []
        for _ in 0..<treeHeight {
            let nLeaves = try BUMPParser.readVarInt(data: data, offset: &offset)
            var leaves: [BUMPLeaf] = []

            for _ in 0..<nLeaves {
                let leafOffset = try BUMPParser.readVarInt(data: data, offset: &offset)
                let flags = try BUMPParser.readByte(data: data, offset: &offset)
                let isDuplicate = (flags & 0x01) != 0
                let isTxid = (flags & 0x02) != 0

                var hash: Data?
                if !isDuplicate {
                    hash = try BUMPParser.readBytes(data: data, offset: &offset, count: 32)
                }

                leaves.append(BUMPLeaf(
                    offset: leafOffset,
                    hash: hash,
                    txid: isTxid,
                    duplicate: isDuplicate
                ))
            }
            levels.append(BUMPLevel(leaves: leaves))
        }

        return BUMP(blockHeight: blockHeight, treeHeight: treeHeight, levels: levels)
    }

    private static func skipRawTransaction(data: Data, offset: inout Int) throws {
        // Propagate truncation as `ParseError.unexpectedEnd` so the caller
        // knows the BEEF was malformed. Previously every guard `return`'d
        // and the caller continued parsing as if everything was fine.
        guard offset + 4 <= data.count else { throw ParseError.unexpectedEnd }
        offset += 4 // version
        let inputCount = try BUMPParser.readVarInt(data: data, offset: &offset)
        for _ in 0..<inputCount {
            guard offset + 36 <= data.count else { throw ParseError.unexpectedEnd }
            offset += 32 // prev txid
            offset += 4  // prev index
            let scriptLen = try BUMPParser.readVarInt(data: data, offset: &offset)
            offset = try offsetAfterScript(ofLength: scriptLen, from: offset, trailing: 4, in: data)
            offset += 4  // sequence
        }
        let outputCount = try BUMPParser.readVarInt(data: data, offset: &offset)
        for _ in 0..<outputCount {
            guard offset + 8 <= data.count else { throw ParseError.unexpectedEnd }
            offset += 8  // satoshis
            let scriptLen = try BUMPParser.readVarInt(data: data, offset: &offset)
            offset = try offsetAfterScript(ofLength: scriptLen, from: offset, trailing: 0, in: data)
        }
        guard offset + 4 <= data.count else { throw ParseError.unexpectedEnd }
        offset += 4 // locktime
    }

    /// The offset advanced past a script of `scriptLen` bytes.
    ///
    /// `scriptLen` is a varint from untrusted BEEF, so a plain `Int(scriptLen)`
    /// or `offset + Int(scriptLen)` could trap on a value that overflows `Int`.
    /// Here the conversion and the arithmetic are done without trapping: a
    /// length unrepresentable as `Int`, or whose arithmetic overflows, throws
    /// `.invalidData`; a representable length that simply runs past the buffer
    /// throws `.unexpectedEnd`. `trailing` is the count of fixed bytes that must
    /// also fit after the script — 4 for an input's sequence field, 0 for an
    /// output.
    private static func offsetAfterScript(
        ofLength scriptLen: UInt64, from offset: Int, trailing: Int, in data: Data
    ) throws -> Int {
        guard let length = Int(exactly: scriptLen) else { throw ParseError.invalidData }
        let (afterScript, scriptOverflow) = offset.addingReportingOverflow(length)
        let (afterTrailing, trailingOverflow) = afterScript.addingReportingOverflow(trailing)
        guard !scriptOverflow, !trailingOverflow else { throw ParseError.invalidData }
        guard afterTrailing <= data.count else { throw ParseError.unexpectedEnd }
        return afterScript
    }
}

// MARK: - BEEF Builder

public enum BEEFBuilder {

    /// Build a BEEF envelope from a transaction and its parent transactions.
    ///
    /// - Parameters:
    ///   - rawTx: The raw transaction bytes to package
    ///   - parentTxs: Parent transactions as raw bytes, keyed by txid
    ///   - bumpsByTxid: BUMPs for parent transactions, keyed by txid
    /// - Returns: Serialized BEEF bytes, or nil if no parents available
    public static func build(
        rawTx: Data,
        parentTxs: [String: Data],
        bumpsByTxid: [String: BUMP] = [:]
    ) -> Data? {
        guard !parentTxs.isEmpty else { return nil }

        var bumps: [BUMP] = []
        var bumpIndexByTxid: [String: UInt64] = [:]

        for (txid, bump) in bumpsByTxid {
            guard parentTxs[txid] != nil else { continue }
            let index = UInt64(bumps.count)
            bumps.append(bump)
            bumpIndexByTxid[txid] = index
        }

        var transactions: [BEEFTransaction] = []

        for (txid, rawParent) in parentTxs.sorted(by: { $0.key < $1.key }) {
            let hasBUMP = bumpIndexByTxid[txid] != nil
            transactions.append(BEEFTransaction(
                rawTx: rawParent,
                hasBUMP: hasBUMP,
                bumpIndex: bumpIndexByTxid[txid]
            ))
        }

        transactions.append(BEEFTransaction(
            rawTx: rawTx,
            hasBUMP: false,
            bumpIndex: nil
        ))

        let beef = BEEF(bumps: bumps, transactions: transactions)
        return BEEFParser.serialize(beef)
    }
}
