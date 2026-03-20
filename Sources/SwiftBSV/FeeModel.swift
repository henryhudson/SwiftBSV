//
//  FeeModel.swift
//  SwiftBSV
//
//  Transaction fee estimation utilities.
//  Standalone fee calculation without requiring a full TxBuilder.
//
//  Standard P2PKH sizes:
//    Input:  148 bytes (txid 32 + vout 4 + scriptLen 1 + scriptSig ~107 + sequence 4)
//    Output: 34 bytes  (value 8 + scriptLen 1 + P2PKH script 25)
//    Overhead: 10 bytes (version 4 + inputCount 1 + outputCount 1 + locktime 4)
//

import Foundation

public struct FeeModel {

    /// Fee rate in satoshis per kilobyte
    public let satoshisPerKb: Double

    /// Fee rate in satoshis per byte
    public var satoshisPerByte: Double {
        satoshisPerKb / 1000.0
    }

    /// Default BSV fee rate (0.5 sat/kb = 0.0005 sat/byte)
    public static let defaultRate = FeeModel(satoshisPerKb: 0.5)

    /// Standard 1 sat/kb rate
    public static let standard = FeeModel(satoshisPerKb: 1.0)

    public init(satoshisPerKb: Double) {
        self.satoshisPerKb = satoshisPerKb
    }

    /// Initialize from satoshis/bytes (e.g. from ARC mining fee policy)
    public init(satoshis: Int, bytes: Int) {
        guard bytes > 0 else {
            self.satoshisPerKb = 500.0 // 0.5 sat/byte default
            return
        }
        self.satoshisPerKb = Double(satoshis) / Double(bytes) * 1000.0
    }

    // MARK: - Size Constants

    /// Estimated size of a compressed P2PKH input (bytes)
    public static let p2pkhInputSize = 148

    /// Estimated size of a P2PKH output (bytes)
    public static let p2pkhOutputSize = 34

    /// Transaction overhead: version (4) + input count (1) + output count (1) + locktime (4)
    public static let txOverhead = 10

    // MARK: - Fee Estimation

    /// Estimate fee for a given transaction size in bytes.
    /// Adds a 2-satoshi buffer to prevent rounding rejections.
    public func feeForSize(_ sizeBytes: Int) -> Int {
        Int(ceil(Double(sizeBytes) * satoshisPerByte)) + 2
    }

    /// Estimate fee for a standard P2PKH transaction.
    /// - Parameters:
    ///   - inputCount: Number of P2PKH inputs
    ///   - p2pkhOutputCount: Number of P2PKH outputs (including change)
    ///   - opReturnSize: Total size of OP_RETURN data (0 if none). Adds 11 bytes overhead per OP_RETURN.
    /// - Returns: Estimated fee in satoshis
    public func estimateP2PKHFee(
        inputCount: Int,
        p2pkhOutputCount: Int,
        opReturnSize: Int = 0
    ) -> Int {
        let size = estimateP2PKHSize(
            inputCount: inputCount,
            p2pkhOutputCount: p2pkhOutputCount,
            opReturnSize: opReturnSize
        )
        return feeForSize(size)
    }

    /// Estimate the byte size of a standard P2PKH transaction.
    public func estimateP2PKHSize(
        inputCount: Int,
        p2pkhOutputCount: Int,
        opReturnSize: Int = 0
    ) -> Int {
        var size = FeeModel.txOverhead
        size += inputCount * FeeModel.p2pkhInputSize
        size += p2pkhOutputCount * FeeModel.p2pkhOutputSize
        if opReturnSize > 0 {
            size += 11 + opReturnSize // OP_FALSE(1) + OP_RETURN(1) + pushdata(1-9) + value(8)
        }
        return size
    }

    /// Calculate the minimum UTXO value that is economical to spend at this fee rate.
    /// UTXOs below this value cost more in fees than they're worth.
    public var dustThreshold: Int {
        // An input costs ~148 bytes × fee rate to spend
        // If the UTXO value is less than the cost to spend it, it's dust
        Int(ceil(Double(FeeModel.p2pkhInputSize) * satoshisPerByte)) + 1
    }
}
