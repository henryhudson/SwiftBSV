//
//  BUMP.swift
//  SwiftBSV
//
//  BRC-74: Binary Unified Merkle Path (BUMP) format.
//  Complete parser, serializer, and Merkle proof conversion.
//

import Foundation
import CryptoSwift

// MARK: - BUMP Structures

/// A leaf node in a BUMP Merkle tree level
public struct BUMPLeaf {
    public let offset: UInt64
    public let hash: Data?       // 32 bytes, nil if duplicate
    public let txid: Bool        // true if this hash is a client transaction ID
    public let duplicate: Bool   // true if hash is computed from prior level

    public init(offset: UInt64, hash: Data?, txid: Bool, duplicate: Bool) {
        self.offset = offset
        self.hash = hash
        self.txid = txid
        self.duplicate = duplicate
    }
}

/// One level of a BUMP Merkle tree
public struct BUMPLevel {
    public let leaves: [BUMPLeaf]

    public init(leaves: [BUMPLeaf]) {
        self.leaves = leaves
    }
}

/// A complete BUMP (Binary Unified Merkle Path) per BRC-74
public struct BUMP {
    public let blockHeight: UInt64
    public let treeHeight: UInt8
    public let levels: [BUMPLevel]

    public init(blockHeight: UInt64, treeHeight: UInt8, levels: [BUMPLevel]) {
        self.blockHeight = blockHeight
        self.treeHeight = treeHeight
        self.levels = levels
    }

    /// Extract all transaction IDs referenced in this BUMP
    public var txids: [String] {
        levels.flatMap { level in
            level.leaves.compactMap { leaf in
                guard leaf.txid, let hash = leaf.hash else { return nil }
                return Data(hash.reversed()).hex
            }
        }
    }

    /// Convert to a MerkleProof for use with SPV verification.
    ///
    /// Returns nil on:
    /// - `txid` is not present in level 0
    /// - tree is empty
    /// - any level on the path lacks a sibling for the current offset
    ///   (previously this silently produced a truncated proof; the
    ///   verifier would then return `false` "for the right reason" only
    ///   by accident, masking the malformed-input cause)
    /// - `foundLeaf.offset >= 2^treeHeight` (path would walk off the tree)
    public func toMerkleProof(txid: String, merkleRoot: String, blockHash: String) -> MerkleProof? {
        let txidBytes = Data(Data(hex: txid).reversed())
        guard let level0 = levels.first else { return nil }

        var txLeaf: BUMPLeaf?
        for leaf in level0.leaves {
            if leaf.txid, leaf.hash == txidBytes {
                txLeaf = leaf
                break
            }
        }
        guard let foundLeaf = txLeaf else { return nil }

        // Bound check: the leaf offset must fit inside the declared tree.
        if treeHeight < 63, foundLeaf.offset >= (UInt64(1) << UInt64(treeHeight)) {
            return nil
        }

        let index = Int(foundLeaf.offset)

        // Collect sibling hashes from each level, tracking the running hash
        // so duplicate leaves can be resolved correctly (BRC-74 section 3.4).
        var nodes: [String] = []
        var currentOffset = foundLeaf.offset
        var currentHash = txid
        for level in levels {
            let siblingOffset = currentOffset ^ 1
            var foundSibling = false
            for leaf in level.leaves where leaf.offset == siblingOffset {
                if leaf.duplicate {
                    nodes.append(currentHash)
                    foundSibling = true
                } else if let hash = leaf.hash {
                    nodes.append(Data(hash.reversed()).hex)
                    foundSibling = true
                }
                break
            }
            // Reject a truncated path. Returning a partial proof would
            // produce a "false" from the verifier, but the failure mode
            // would be indistinguishable from a forged proof — the
            // structural break belongs at the source.
            guard foundSibling else { return nil }

            let siblingHex = nodes.last!
            let isLeft = (currentOffset % 2 == 0)
            if isLeft {
                currentHash = BUMP.hashPair(left: currentHash, right: siblingHex)
            } else {
                currentHash = BUMP.hashPair(left: siblingHex, right: currentHash)
            }
            currentOffset /= 2
        }

        return MerkleProof(
            txid: txid,
            blockHash: blockHash,
            blockHeight: Int(blockHeight),
            merkleRoot: merkleRoot,
            index: index,
            nodes: nodes
        )
    }

    /// Bitcoin double-SHA256 on a pair of display-order hex hashes.
    public static func hashPair(left: String, right: String) -> String {
        let leftData = Data(hex: left)
        let rightData = Data(hex: right)
        guard !leftData.isEmpty, !rightData.isEmpty else { return "" }
        var combined = Data(leftData.reversed())
        combined.append(Data(rightData.reversed()))
        let hash1 = Data(combined).sha256()
        let hash2 = Data(hash1).sha256()
        return Data(Data(hash2).reversed()).hex
    }
}

// MARK: - BUMP Parser

public enum BUMPParser {

    public enum ParseError: Error, LocalizedError {
        case invalidData
        case unexpectedEnd
        case invalidFlags(UInt8)

        public var errorDescription: String? {
            switch self {
            case .invalidData: return "Invalid BUMP data"
            case .unexpectedEnd: return "Unexpected end of BUMP data"
            case .invalidFlags(let f): return "Invalid BUMP leaf flags: \(f)"
            }
        }
    }

    /// Parse a BUMP from hex string
    public static func parse(hex: String) throws -> BUMP {
        let data = Data(hex: hex)
        guard !data.isEmpty else { throw ParseError.invalidData }
        return try parse(data: data)
    }

    /// Parse a BUMP from raw bytes
    public static func parse(data: Data) throws -> BUMP {
        var offset = 0

        let blockHeight = try readVarInt(data: data, offset: &offset)
        let treeHeight = try readByte(data: data, offset: &offset)

        var levels: [BUMPLevel] = []

        for _ in 0..<treeHeight {
            let nLeaves = try readVarInt(data: data, offset: &offset)
            var leaves: [BUMPLeaf] = []

            for _ in 0..<nLeaves {
                let leafOffset = try readVarInt(data: data, offset: &offset)
                let flags = try readByte(data: data, offset: &offset)

                let isDuplicate = (flags & 0x01) != 0
                let isTxid = (flags & 0x02) != 0

                var hash: Data?
                if !isDuplicate {
                    hash = try readBytes(data: data, offset: &offset, count: 32)
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

    /// Serialize a BUMP to binary
    public static func serialize(_ bump: BUMP) -> Data {
        var data = Data()
        writeVarInt(bump.blockHeight, to: &data)
        data.append(bump.treeHeight)

        for level in bump.levels {
            writeVarInt(UInt64(level.leaves.count), to: &data)
            for leaf in level.leaves {
                writeVarInt(leaf.offset, to: &data)
                var flags: UInt8 = 0
                if leaf.duplicate { flags |= 0x01 }
                if leaf.txid { flags |= 0x02 }
                data.append(flags)
                if !leaf.duplicate, let hash = leaf.hash {
                    data.append(hash)
                }
            }
        }

        return data
    }

    // MARK: - VarInt Helpers

    public static func readVarInt(data: Data, offset: inout Int) throws -> UInt64 {
        guard offset < data.count else { throw ParseError.unexpectedEnd }
        let first = data[offset]
        offset += 1

        switch first {
        case 0x00...0xFC:
            return UInt64(first)
        case 0xFD:
            guard offset + 2 <= data.count else { throw ParseError.unexpectedEnd }
            let value = UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
            offset += 2
            return UInt64(value)
        case 0xFE:
            guard offset + 4 <= data.count else { throw ParseError.unexpectedEnd }
            let value = UInt32(data[offset])
                | (UInt32(data[offset + 1]) << 8)
                | (UInt32(data[offset + 2]) << 16)
                | (UInt32(data[offset + 3]) << 24)
            offset += 4
            return UInt64(value)
        default:
            guard offset + 8 <= data.count else { throw ParseError.unexpectedEnd }
            var value: UInt64 = 0
            for i in 0..<8 {
                value |= UInt64(data[offset + i]) << (i * 8)
            }
            offset += 8
            return value
        }
    }

    public static func readByte(data: Data, offset: inout Int) throws -> UInt8 {
        guard offset < data.count else { throw ParseError.unexpectedEnd }
        let byte = data[offset]
        offset += 1
        return byte
    }

    public static func readBytes(data: Data, offset: inout Int, count: Int) throws -> Data {
        guard offset + count <= data.count else { throw ParseError.unexpectedEnd }
        let bytes = data[offset..<(offset + count)]
        offset += count
        return Data(bytes)
    }

    public static func writeVarInt(_ value: UInt64, to data: inout Data) {
        if value <= 0xFC {
            data.append(UInt8(value))
        } else if value <= 0xFFFF {
            data.append(0xFD)
            data.append(UInt8(value & 0xFF))
            data.append(UInt8((value >> 8) & 0xFF))
        } else if value <= 0xFFFFFFFF {
            data.append(0xFE)
            for i in 0..<4 {
                data.append(UInt8((value >> (i * 8)) & 0xFF))
            }
        } else {
            data.append(0xFF)
            for i in 0..<8 {
                data.append(UInt8((value >> (i * 8)) & 0xFF))
            }
        }
    }
}
