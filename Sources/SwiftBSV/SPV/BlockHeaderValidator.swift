//
//  BlockHeaderValidator.swift
//  SwiftBSV
//
//  Validates block headers according to Bitcoin consensus rules.
//  Implements proof-of-work verification and chain linking validation.
//

import Foundation
import CryptoSwift

// MARK: - Block Header Protocol

/// Protocol for block headers used in SPV validation.
/// Conforming types (e.g. WhatsOnChain API models) can be validated directly.
public protocol BlockHeader {
    var hash: String { get }
    var height: Int { get }
    var version: Int { get }
    var merkleroot: String { get }
    var time: Date { get }
    var nonce: Int { get }
    var bits: String { get }
    var previousblockhash: String { get }
}

// MARK: - Block Header Validator

/// Validates block headers according to Bitcoin consensus rules.
public struct BlockHeaderValidator: Sendable {

    public init() {}

    /// Validate a single block header's proof-of-work.
    public func validateProofOfWork<H: BlockHeader>(header: H) -> Bool {
        guard let calculatedHash = calculateBlockHash(header: header) else {
            return false
        }

        guard let hashValue = UInt256(hexString: calculatedHash) else {
            return false
        }

        guard let target = targetFromBits(bits: header.bits) else {
            return false
        }

        return hashValue < target
    }

    /// Validate that a block header correctly links to its parent.
    public func validateChainLink<H: BlockHeader>(header: H, previousHeader: H) -> Bool {
        guard header.height == previousHeader.height + 1 else {
            return false
        }

        return header.previousblockhash.lowercased() == previousHeader.hash.lowercased()
    }

    /// Validate a chain of block headers (PoW + chain linking).
    public func validateHeaderChain<H: BlockHeader>(headers: [H]) -> ChainValidationResult {
        guard !headers.isEmpty else {
            return ChainValidationResult(isValid: false, validatedCount: 0, errorMessage: "Empty header chain")
        }

        let sortedHeaders = headers.sorted { $0.height < $1.height }
        var validatedCount = 0

        if !validateProofOfWork(header: sortedHeaders[0]) {
            return ChainValidationResult(
                isValid: false,
                validatedCount: 0,
                errorMessage: "First header PoW validation failed at height \(sortedHeaders[0].height)"
            )
        }
        validatedCount += 1

        for i in 1..<sortedHeaders.count {
            let currentHeader = sortedHeaders[i]
            let previousHeader = sortedHeaders[i - 1]

            if !validateProofOfWork(header: currentHeader) {
                return ChainValidationResult(
                    isValid: false,
                    validatedCount: validatedCount,
                    errorMessage: "PoW validation failed at height \(currentHeader.height)"
                )
            }

            if !validateChainLink(header: currentHeader, previousHeader: previousHeader) {
                return ChainValidationResult(
                    isValid: false,
                    validatedCount: validatedCount,
                    errorMessage: "Chain link validation failed at height \(currentHeader.height)"
                )
            }

            validatedCount += 1
        }

        return ChainValidationResult(isValid: true, validatedCount: validatedCount, errorMessage: nil)
    }

    // MARK: - Block Hashing

    /// Calculate the double SHA-256 hash of a block header.
    public func calculateBlockHash<H: BlockHeader>(header: H) -> String? {
        guard let headerData = serializeBlockHeader(header: header) else {
            return nil
        }

        let hash1 = Data(headerData).sha256()
        let hash2 = Data(hash1).sha256()

        return Data(Data(hash2).reversed()).hex
    }

    /// Serialize a block header into 80 bytes (Bitcoin wire format).
    public func serializeBlockHeader<H: BlockHeader>(header: H) -> Data? {
        var data = Data()

        // Version (4 bytes, little-endian)
        data.append(UInt32(header.version).littleEndianData)

        // Previous block hash (32 bytes, reversed)
        let prevHashData = Data(hex: header.previousblockhash)
        guard prevHashData.count == 32 else { return nil }
        data.append(Data(prevHashData.reversed()))

        // Merkle root (32 bytes, reversed)
        let merkleRootData = Data(hex: header.merkleroot)
        guard merkleRootData.count == 32 else { return nil }
        data.append(Data(merkleRootData.reversed()))

        // Timestamp (4 bytes, little-endian)
        let timestamp = UInt32(header.time.timeIntervalSince1970)
        data.append(timestamp.littleEndianData)

        // Bits (4 bytes, little-endian)
        let bitsData = Data(hex: header.bits)
        guard bitsData.count == 4 else { return nil }
        data.append(Data(bitsData.reversed()))

        // Nonce (4 bytes, little-endian)
        data.append(UInt32(header.nonce).littleEndianData)

        guard data.count == 80 else { return nil }
        return data
    }

    // MARK: - Target Calculation

    /// Convert compact bits representation to target value.
    public func targetFromBits(bits: String) -> UInt256? {
        let bitsData = Data(hex: bits)
        guard bitsData.count == 4 else { return nil }

        let bytes = [UInt8](Data(bitsData.reversed()))
        let exponent = Int(bytes[3])
        let coefficient = UInt32(bytes[0]) | (UInt32(bytes[1]) << 8) | (UInt32(bytes[2]) << 16)

        guard exponent >= 3 else { return nil }

        return UInt256(coefficient) << ((exponent - 3) * 8)
    }
}

// MARK: - Chain Validation Result

/// Result of chain validation
public struct ChainValidationResult: Sendable {
    public let isValid: Bool
    public let validatedCount: Int
    public let errorMessage: String?

    public init(isValid: Bool, validatedCount: Int, errorMessage: String?) {
        self.isValid = isValid
        self.validatedCount = validatedCount
        self.errorMessage = errorMessage
    }

    public var description: String {
        if isValid {
            return "Chain valid: \(validatedCount) headers verified"
        } else {
            return "Chain invalid: \(errorMessage ?? "Unknown error") (validated \(validatedCount) headers)"
        }
    }
}

// MARK: - UInt256

/// 256-bit unsigned integer for hash/target comparisons.
/// Internal storage is big-endian: index 0 = MSB, index 31 = LSB.
public struct UInt256: Comparable {
    private var data: Data

    public init(_ value: UInt32) {
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[28] = UInt8((value >> 24) & 0xFF)
        bytes[29] = UInt8((value >> 16) & 0xFF)
        bytes[30] = UInt8((value >> 8) & 0xFF)
        bytes[31] = UInt8(value & 0xFF)
        self.data = Data(bytes)
    }

    public init?(hexString: String) {
        let d = Data(hex: hexString)
        guard d.count == 32 else { return nil }
        self.data = d
    }

    public init(data: Data) {
        if data.count < 32 {
            var padded = Data(repeating: 0, count: 32 - data.count)
            padded.append(data)
            self.data = padded
        } else {
            self.data = data
        }
    }

    public static func << (lhs: UInt256, rhs: Int) -> UInt256 {
        let byteShift = rhs / 8
        let bitShift = rhs % 8

        var result = [UInt8](repeating: 0, count: 32)
        var carry: UInt16 = 0

        for i in stride(from: 31, through: 0, by: -1) {
            let sourceIndex = i + byteShift
            let sourceByte: UInt16 = (sourceIndex >= 0 && sourceIndex < 32) ? UInt16(lhs.data[sourceIndex]) : 0

            let shifted = (sourceByte << bitShift) | carry
            result[i] = UInt8(shifted & 0xFF)
            carry = shifted >> 8
        }

        return UInt256(data: Data(result))
    }

    public static func < (lhs: UInt256, rhs: UInt256) -> Bool {
        for i in 0..<32 {
            if lhs.data[i] < rhs.data[i] { return true }
            else if lhs.data[i] > rhs.data[i] { return false }
        }
        return false
    }

    public static func == (lhs: UInt256, rhs: UInt256) -> Bool {
        return lhs.data == rhs.data
    }

    public var hexString: String {
        return data.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - UInt32 Extension

extension UInt32 {
    public var littleEndianData: Data {
        var value = self.littleEndian
        return Data(bytes: &value, count: MemoryLayout<UInt32>.size)
    }
}
