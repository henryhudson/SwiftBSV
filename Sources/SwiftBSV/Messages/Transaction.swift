//
//  Transaction.swift
//
//  Copyright © 2018 Kishikawa Katsumi
//  Copyright © 2018 BitcoinKit developers
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import Foundation

/// tx describes a bitcoin transaction, in reply to getdata
public struct Transaction: Equatable {
    /// Transaction data format version (note, this is signed)
    public var version: UInt32
    /// If present, always 0001, and indicates the presence of witness data
    // public let flag: UInt16 // If present, always 0001, and indicates the presence of witness data
    /// Number of Transaction inputs (never zero)
    public var txInCount: VarInt {
        return VarInt(inputs.count)
    }
    /// A list of 1 or more transaction inputs or sources for coins
    public var inputs: [TransactionInput]
    /// Number of Transaction outputs
    public var txOutCount: VarInt {
        return VarInt(outputs.count)
    }
    /// A list of 1 or more transaction outputs or destinations for coins
    public var outputs: [TransactionOutput]
    /// A list of witnesses, one for each input; omitted if flag is omitted above
    // public let witnesses: [TransactionWitness] // A list of witnesses, one for each input; omitted if flag is omitted above
    /// The block number or timestamp at which this transaction is unlocked:
    public var lockTime: UInt32

    public var txHash: Data {
        return Crypto.sha256sha256(serialized())
    }

    public var txID: String {
        return Data(txHash.reversed()).hex
    }

    static var empty = Transaction(version: 1, inputs: [], outputs: [], lockTime: 0)

    public init(version: UInt32, inputs: [TransactionInput], outputs: [TransactionOutput], lockTime: UInt32) {
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.lockTime = lockTime
    }

    public func serialized() -> Data {
        var data = Data()
        data += version
        data += txInCount.serialized()
        data += inputs.flatMap { $0.serialized() }
        data += txOutCount.serialized()
        data += outputs.flatMap { $0.serialized() }
        data += lockTime
        return data
    }

    public func isCoinbase() -> Bool {
        return inputs.count == 1 && inputs[0].isCoinbase()
    }

    public static func deserialize(_ data: Data) -> Transaction {
        let byteStream = ByteStream(data)
        return deserialize(byteStream)
    }

    static func deserialize(_ byteStream: ByteStream) -> Transaction {
        let version = byteStream.read(UInt32.self)
        let txInCount = byteStream.read(VarInt.self)
        var inputs = [TransactionInput]()
        for _ in 0..<Int(txInCount.underlyingValue) {
            inputs.append(TransactionInput.deserialize(byteStream))
        }
        let txOutCount = byteStream.read(VarInt.self)
        var outputs = [TransactionOutput]()
        for _ in 0..<Int(txOutCount.underlyingValue) {
            outputs.append(TransactionOutput.deserialize(byteStream))
        }
        let lockTime = byteStream.read(UInt32.self)
        return Transaction(version: version, inputs: inputs, outputs: outputs, lockTime: lockTime)
    }
}

// MARK: - Transaction + TxBuilder

extension Transaction {

    @discardableResult
    mutating func addTransactionInput(_ input: TransactionInput) -> Self {
        inputs.append(input)
        return self
    }

    @discardableResult
    mutating func addTransactionInput(txHashBuffer: Data, txOutNum: UInt32, script: Script, nSequence: UInt32) -> Self {

        let transactionInput = TransactionInput(
            previousOutput: TransactionOutPoint(
                hash: txHashBuffer,
                index: txOutNum
            ),
            signatureScript: script.data,
            sequence: nSequence
        )

        inputs.append(transactionInput)
        return self
    }

    @discardableResult
    mutating func addTransactionOutput(_ output: TransactionOutput) -> Self {
        outputs.append(output)
        return self
    }

    @discardableResult
    mutating func addTransactionOutput(value: UInt64, lockingScript: Script) -> Self {
        let output = TransactionOutput(value: value, lockingScript: lockingScript.data)
        outputs.append(output)
        return self
    }

    mutating func removeLastTransactionOutput() -> TransactionOutput? {
        return outputs.popLast()
    }

    mutating func setVersion(_ version: UInt32) {
        self.version = version
    }

    mutating func setLockTime(_ nLockTime: UInt32) {
        self.lockTime = nLockTime
    }

    /// BIP-69 deterministic sorting of inputs and outputs. Must be called
    /// before signing — the digest covers the (sorted) input/output array.
    ///
    /// Inputs sorted ascending by (prev txid in big-endian display order,
    /// then prev vout). Outputs sorted ascending by (value, then locking
    /// script bytes lexicographically).
    ///
    /// White paper §10 (Privacy): canonical ordering removes "this is the
    /// X wallet" fingerprinting from the wire format.
    public mutating func sort() {
        inputs.sort { lhs, rhs in
            // Compare txids in big-endian (display) order — that's the
            // BIP-69 contract and matches what users see in explorers.
            let lTxid = Data(lhs.previousOutput.hash.reversed())
            let rTxid = Data(rhs.previousOutput.hash.reversed())
            if lTxid != rTxid {
                return lexicographicallyLessThan(lTxid, rTxid)
            }
            return lhs.previousOutput.index < rhs.previousOutput.index
        }
        outputs.sort { lhs, rhs in
            if lhs.value != rhs.value {
                return lhs.value < rhs.value
            }
            return lexicographicallyLessThan(lhs.lockingScript, rhs.lockingScript)
        }
    }

    mutating func fillSig(nIn: Int, nScriptChunk: Int, sig: Data, sighashType: SighashType, publicKey: PublicKey) {
        var inputs = self.inputs
        let input = inputs[nIn]
        let sigWithType = sig + [UInt8(sighashType.sighash)]
        let unlockingScript = try! Script()
            .appendData(sigWithType)
            .appendData(publicKey.toDer())

        let unlockedTransactionInput = TransactionInput(
            previousOutput: input.previousOutput,
            signatureScript: unlockingScript.data,
            sequence: input.sequence
        )

        inputs[nIn] = unlockedTransactionInput
        self.inputs = inputs
    }

}

// MARK: - Transaction + SigHash

extension Transaction {

    /// Sign and return the signature
    func sign(privateKey: PrivateKey, sighashType: SighashType, nIn: Int, subScript: Script, value: UInt64, signatureVersion: SignatureVersion = .forkId) -> Data {
        let hashBuf = TransactionInputSigner.signatureHash(tx: self, signatureVersion: signatureVersion, sighashType: sighashType, nIn: nIn, subScript: subScript, value: value)

        let hashBufRev = Data(hashBuf.reversed())
        let sig = Crypto.sign(hashBufRev, privateKey: privateKey)
        return sig
    }

}

/// Big-endian byte-by-byte less-than. Two equal-prefix arrays use length
/// as tiebreaker (shorter is "less"), matching BIP-69's reference behaviour.
private func lexicographicallyLessThan(_ lhs: Data, _ rhs: Data) -> Bool {
    let count = min(lhs.count, rhs.count)
    let lStart = lhs.startIndex
    let rStart = rhs.startIndex
    for i in 0..<count {
        let l = lhs[lStart + i]
        let r = rhs[rStart + i]
        if l != r { return l < r }
    }
    return lhs.count < rhs.count
}

struct TransactionSigHashFlags: OptionSet {
    let rawValue: Int

    static let none = TransactionSigHashFlags(rawValue: 1 << 0)
    static let scriptEnableSighashForkId = TransactionSigHashFlags(rawValue: 1 << 16)

    static let all: TransactionSigHashFlags = [.none, .scriptEnableSighashForkId]
}
