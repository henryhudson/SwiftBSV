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
public struct BEEFTransaction {
    public let rawTx: Data
    public let hasBUMP: Bool
    public let bumpIndex: UInt64?

    public init(rawTx: Data, hasBUMP: Bool, bumpIndex: UInt64?) {
        self.rawTx = rawTx
        self.hasBUMP = hasBUMP
        self.bumpIndex = bumpIndex
    }
}

/// Background Evaluation Extended Format (BRC-62).
/// Bundles transactions with their Merkle proofs for offline SPV verification.
public struct BEEF {
    public static let versionMarker: UInt32 = 0x0100_BEEF

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

        guard version == BEEF.versionMarker else {
            throw ParseError.invalidVersion(version)
        }

        let nBumps = try BUMPParser.readVarInt(data: data, offset: &offset)
        var bumps: [BUMP] = []
        for _ in 0..<nBumps {
            let bump = try parseBUMPInline(data: data, offset: &offset)
            bumps.append(bump)
        }

        let nTxs = try BUMPParser.readVarInt(data: data, offset: &offset)
        var transactions: [BEEFTransaction] = []
        for _ in 0..<nTxs {
            let txStart = offset
            skipRawTransaction(data: data, offset: &offset)
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
        for tx in beef.transactions {
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

    private static func skipRawTransaction(data: Data, offset: inout Int) {
        guard offset + 4 <= data.count else { return }
        offset += 4 // version
        guard let inputCount = try? BUMPParser.readVarInt(data: data, offset: &offset) else { return }
        for _ in 0..<inputCount {
            guard offset + 36 <= data.count else { return }
            offset += 32 // prev txid
            offset += 4  // prev index
            guard let scriptLen = try? BUMPParser.readVarInt(data: data, offset: &offset),
                  offset + Int(scriptLen) + 4 <= data.count else { return }
            offset += Int(scriptLen)
            offset += 4  // sequence
        }
        guard let outputCount = try? BUMPParser.readVarInt(data: data, offset: &offset) else { return }
        for _ in 0..<outputCount {
            guard offset + 8 <= data.count else { return }
            offset += 8  // satoshis
            guard let scriptLen = try? BUMPParser.readVarInt(data: data, offset: &offset),
                  offset + Int(scriptLen) <= data.count else { return }
            offset += Int(scriptLen)
        }
        guard offset + 4 <= data.count else { return }
        offset += 4 // locktime
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
