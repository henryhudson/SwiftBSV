//
//  TxBuilder.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-18.
//  Copyright © 2020 wtsnz. All rights reserved.
//

import Foundation

enum TxBuilderError: Error {
    case invalidNumberOfInputs
    case missingChangeOutput
    case invalidNumberOfOutputs
    case changeOutputLessThanDust
    case inputAmountLessThanOutputAmount
    /// `signInTx` was called for a previous-output that wasn't
    /// pre-populated in `uTxOutMap` and no `txOut` argument was passed.
    /// Includes the txid:vout for traceability.
    case missingPrevOut(txid: String, vout: UInt32)
    /// `buildInputs` could not find the previous-output for one of the
    /// added inputs in `uTxOutMap`.
    case missingPrevOutDuringBuild(txid: String, vout: UInt32)
    /// The signature script of an existing input could not be parsed.
    case malformedSignatureScript(nIn: Int)
    /// The locking (output) script of a referenced UTXO could not be parsed.
    case malformedLockingScript(nIn: Int)
}

/// `TxBuilder` is a value type. The public API is split by intent:
///
/// **Configuration setters** (`setNLockTime`, `setVersion`, `setFeePerKb`,
/// `setChangeAddress`, `setChangeScript`) are **non-mutating** and return
/// a new builder. Designed for the chain-and-capture pattern:
///
///     let txb = TxBuilder()
///         .setFeePerKb(500)
///         .setChangeAddress(addr)
///         .setNLockTime(0)
///
/// They deliberately drop `@discardableResult` — calling
/// `b.setFeePerKb(500)` on a `var b` and discarding the return is a
/// programmer error (no effect on `b`), and the compiler now warns.
///
/// **State-mutating ops** (`inputFromX`, `outputToX`, `addSigOperation`,
/// `build`, `signInTx`, `fillSig`) are `mutating` and modify `self` in
/// place. They keep `@discardableResult` (the mutation is real even when
/// the return is discarded) and return `Self` for ergonomic chaining on
/// `var` bindings.
///
/// Was a `class` for no reason — no shared identity, no inheritance, no
/// reference-semantics requirement. Converting to `struct` removes a
/// class of identity-vs-equality bugs and makes the configuration ⇄
/// state-mutation split enforceable at the type level.
public struct TxBuilder {

    private(set) public var transaction: Transaction = .empty
    private var transactionInputs: [TransactionInput] = []
    private var transactionOutputs: [TransactionOutput] = []

    private var uTxOutMap = TxOutMap()
    private var sigOperations = SigOperations()

    private(set) var changeScript: Script?
    /// Spendable change amount left over after fees. `0` means no change
    /// (either by construction or because the change-output value fell
    /// below `dust` and `dustChangeToFees` rolled it into the fee).
    /// Previously `UInt64?` with `nil` indistinguishable from `0`; the
    /// `build()` flow always set it to `0` before reading, so the Optional
    /// was decorative — every read site force-unwrapped.
    private(set) var changeAmount: UInt64 = 0

    private(set) var feeAmount: UInt64 = 0
    private(set) var dustChangeToFees = true

    private(set) var nLockTime: UInt32 = 0
    private(set) var version: UInt32 = 1

    /// The desired fee per Kb (satoshis per 1000 bytes).
    /// Integer rather than Float so fees are deterministic across
    /// architectures — see `estimateFee` for the rounding rule.
    private(set) var dust: UInt64 = Network.mainnet.txBuilder.dust
    private(set) var feePerKbNum: UInt64 = Network.mainnet.txBuilder.feePerKb

    public init() {

    }

    // MARK: - Configuration setters (non-mutating, return new value)

    public func setNLockTime(_ nLockTime: UInt32) -> Self {
        var copy = self
        copy.nLockTime = nLockTime
        return copy
    }

    public func setVersion(_ version: UInt32) -> Self {
        var copy = self
        copy.version = version
        return copy
    }

    public func setFeePerKb(_ fee: UInt64) -> Self {
        var copy = self
        copy.feePerKbNum = fee
        return copy
    }

    public func setChangeAddress(_ changeAddress: Address) -> Self {
        let script: Script = Script.buildPublicKeyHashOut(pubKeyHash: changeAddress.hashBuffer)
        return setChangeScript(script)
    }

    public func setChangeScript(_ changeScript: Script) -> Self {
        var copy = self
        copy.changeScript = changeScript
        return copy
    }

    // MARK: - State-mutating ops (mutating, return Self for chaining on var)

    @discardableResult
    public mutating func inputFromScript(_ txHashBuffer: Data, txOutNum: UInt32, txOut: TransactionOutput, script: Script, nSequence: UInt32) -> Self {
        let txIn = TransactionInput(
            previousOutput: TransactionOutPoint(
                hash: txHashBuffer,
                index: txOutNum
            ),
            signatureScript: script.data,
            sequence: nSequence
        )
        transactionInputs.append(txIn)

        uTxOutMap.set(txHashBuf: txHashBuffer, txOutNum: txOutNum, txOut: txOut)

        return self
    }

    @discardableResult
    public mutating func addSigOperation(_ txHashBuf: Data, txOutNum: UInt32, nScriptChunk: UInt32, type: SigOperation.OperationType, addressString: String, nHashType: SighashType) -> Self {
        sigOperations.addOne(txHashBuf: txHashBuf, txOutNum: txOutNum, nScriptChunk: nScriptChunk, addressString: addressString, nHashType: nHashType)
        return self
    }

    @discardableResult
    public mutating func inputFromPubKeyHash(txHashBuffer: Data, txOutNum: UInt32, txOut: TransactionOutput, pubKey: PublicKey, nSequence: UInt32 = 0xffffffff, nHashType: SighashType = SighashType.BSV.ALL) -> Self {

        let transactionInput = TransactionInput.fromPubKeyHashOut(
            txHashBuf: txHashBuffer,
            txOutNum: txOutNum,
            txOut: txOut,
            pubKey: pubKey
        )

        transactionInputs.append(transactionInput)

        uTxOutMap.set(txHashBuf: txHashBuffer, txOutNum: txOutNum, txOut: txOut)

        let addressString = pubKey.address.toString()
        addSigOperation(txHashBuffer, txOutNum: txOutNum, nScriptChunk: 0, type: .sig, addressString: addressString, nHashType: nHashType)
        addSigOperation(txHashBuffer, txOutNum: txOutNum, nScriptChunk: 1, type: .pubkey, addressString: addressString, nHashType: nHashType)

        return self
    }

    @discardableResult
    public mutating func outputToAddress(value: UInt64, address: Address) -> Self {
        let script: Script = Script.buildPublicKeyHashOut(pubKeyHash: address.hashBuffer)
        outputToScript(value: value, script: script)
        return self
    }

    @discardableResult
    public mutating func outputToScript(value: UInt64, script: Script) -> Self {
        let txOut = TransactionOutput(value: value, lockingScript: script.data)
        transactionOutputs.append(txOut)
        return self
    }

    /// Add the outputs to the transaction and return the total amount.
    /// Side-effect (appending to `transaction`) is intentional and shared
    /// with the caller; pure sum is folded in via `reduce(into:)`.
    mutating func buildOutputs() -> UInt64 {
        // TODO: reject outputs below dust unless they are OP_RETURN /
        // safe-data-out (consensus-relayed null-data scripts).
        transactionOutputs.reduce(into: UInt64(0)) { total, txOut in
            total += txOut.value
            transaction.addTransactionOutput(txOut)
        }
    }

    /// Iterate transactionInputs, accumulating prev-out values until
    /// `outAmount` is met (plus any requested extra). Genuinely sequential
    /// because of the early-exit, so a `for` loop is the right shape;
    /// only the accumulator type was tightened to `UInt64`.
    mutating func buildInputs(outAmount: UInt64, extraInputsNum: UInt32 = 0) throws -> UInt64 {
        var totalInputAmount: UInt64 = 0
        var extraInputsNum = extraInputsNum

        for txIn in transactionInputs {
            guard let txOut = uTxOutMap.get(txHashBuf: txIn.previousOutput.hash, txOutNum: txIn.previousOutput.index) else {
                // Caller appended an input without registering the
                // matching previous-output in uTxOutMap. Surface txid:vout
                // for traceability instead of crashing.
                throw TxBuilderError.missingPrevOutDuringBuild(
                    txid: txIn.previousOutput.hash.hex,
                    vout: txIn.previousOutput.index
                )
            }
            totalInputAmount += txOut.value
            transaction.addTransactionInput(txIn)

            if totalInputAmount >= outAmount {
                if extraInputsNum <= 0 {
                    break
                }
                extraInputsNum -= 1
            }
        }

        return totalInputAmount
    }

    // Thanks to SigOperations, if those are accurately used, then we can
    // accurately estimate what the size of the transaction is going to be once
    // all the signatures and public keys are inserted.
    func estimateSize() -> Int {
        // largest possible sig size. final 1 is for pushdata at start. second to
        // final is sighash byte. the rest are DER encoding.
        let sigSize = 1 + 1 + 1 + 1 + 32 + 1 + 1 + 32 + 1 + 1
        // length of script, y odd, x value - assumes compressed public key
        let pubKeySize = 1 + 1 + 33

        var size = transaction.serialized().count

        for txIn in transactionInputs {
            let sigOperations = self.sigOperations.get(txHashBuf: txIn.previousOutput.hash, txOutNum: txIn.previousOutput.index) ?? []

            for sigOperation in sigOperations {
                size -= Int(txIn.scriptLength.underlyingValue)
                switch sigOperation.type {
                case .pubkey:
                    size += pubKeySize
                case .sig:
                    size += sigSize
                }
            }
        }

        size += 1 // assume txInsVi increases by 1 byte

        return size
    }

    func estimateFee(extraFeeAmount: UInt64 = 0) -> UInt64 {
        // Round UP. UInt64 division truncates; rounding down would let
        // sub-satoshi fees fall through (e.g. a 250-byte tx at 500 sat/kb
        // computes to exactly 125 sat — fine — but a 251-byte tx would
        // compute to 125 sat with truncation when 126 sat is what the
        // network wants). Rounding up never under-pays.
        //
        // Float math previously used here was non-deterministic across
        // architectures and produced occasional "fee too low" rejections
        // at the 0.5-sat boundary. UInt64 is exact and reproducible.
        let size = UInt64(estimateSize())
        let fee = (size * feePerKbNum + 999) / 1000
        return fee + extraFeeAmount
    }

    @discardableResult
    public mutating func build(useAllInputs: Bool) throws -> TxBuilder {
        var minFeeAmount: UInt64 = 0
        self.changeAmount = 0

        if transactionInputs.count <= 0 {
            throw TxBuilderError.invalidNumberOfInputs
        }

        guard let changeScript = changeScript else {
            throw TxBuilderError.missingChangeOutput
        }

        var extraInputsNum = useAllInputs ? UInt32(transactionInputs.count - 1) : 0
        while (extraInputsNum < transactionInputs.count) {

            transaction = Transaction.empty
            let outputAmount = buildOutputs()

            // Add temporary change output transaction.
            let changeTxOut = TransactionOutput(value: changeAmount, lockingScript: changeScript.data)
            transaction.addTransactionOutput(changeTxOut)

            let inputAmount = try buildInputs(outAmount: outputAmount, extraInputsNum: extraInputsNum)

            // Set change amount from inAmountBn - outAmountBn
            changeAmount = inputAmount - outputAmount

            minFeeAmount = estimateFee()
            if changeAmount >= minFeeAmount && (changeAmount - minFeeAmount) > dust {
                break
            }

            extraInputsNum += 1
        }


        // Calculate fee and change
        if changeAmount >= minFeeAmount {

            // Subtract fee from change
            feeAmount = minFeeAmount
            changeAmount = changeAmount - feeAmount

            // Recreate the change transaction output with the correct fee
            _ = transaction.removeLastTransactionOutput()
            let changeTxOut = TransactionOutput(value: changeAmount, lockingScript: changeScript.data)
            transaction.addTransactionOutput(changeTxOut)

            // Check change amount is valid
            if changeAmount < dust {
                if dustChangeToFees {
                    // Remove the change output since it is less that dust and the
                    // builder has requested that dust be sent to fees
                    _ = transaction.removeLastTransactionOutput()
                    feeAmount += changeAmount
                    changeAmount = 0
                } else {
                    throw TxBuilderError.changeOutputLessThanDust
                }
            }

            transaction.setLockTime(nLockTime)
            transaction.setVersion(version)

            if transaction.outputs.count == 0 {
                throw TxBuilderError.invalidNumberOfOutputs
            }

            return self

        } else {
            // not enough input for outputs and fees
            throw TxBuilderError.inputAmountLessThanOutputAmount
        }

    }

    // MARK: - Signatures

    func getSig(privateKey: PrivateKey, sighashType: SighashType = SighashType.BSV.ALL, nIn: Int, subScript: Script, signatureVersion: SignatureVersion = .forkId) -> Data {
        var value = UInt64()

        if sighashType.hasForkId && signatureVersion == .forkId {
            let txHashBuf = transactionInputs[nIn].previousOutput.hash
            let txOutNum = transactionInputs[nIn].previousOutput.index
            if let txOut = uTxOutMap.get(txHashBuf: txHashBuf, txOutNum: txOutNum) {
                value = txOut.value
            }
        }

        return transaction.sign(privateKey: privateKey, sighashType: sighashType, nIn: nIn, subScript: subScript, value: value, signatureVersion: signatureVersion)
    }

    /// Sign the input with the private key. Only supports PayToPublicKeyHash inputs.
    ///
    /// `throws` rather than `fatalError`s on bad inputs (missing prev-out,
    /// unparseable scripts) so callers can surface the error in UI.
    @discardableResult
    public mutating func signInTx(nIn: Int, privateKey: PrivateKey, txOut: TransactionOutput? = nil, nScriptChunk: Int? = nil, sighashType: SighashType = SighashType.BSV.ALL, signatureVersion: SignatureVersion = .forkId) throws -> Self {

        var nScriptChunk = nScriptChunk
        let txIn = transaction.inputs[nIn]
        guard let script = Script(data: txIn.signatureScript) else {
            throw TxBuilderError.malformedSignatureScript(nIn: nIn)
        }

        if nScriptChunk == nil && script.isPubKeyHashIn {
            nScriptChunk = 0
        }

        // Default to chunk 0 if still unset. The previous fatalError here
        // was a "this should never happen" guard; in practice only
        // pubkey-hash inputs are supported by this method, so 0 is the
        // correct chunk index for the standard flow.
        let scriptChunk = nScriptChunk ?? 0

        let txHashBuf = txIn.previousOutput.hash
        let txOutNum = txIn.previousOutput.index

        let resolvedTxOut: TransactionOutput
        if let provided = txOut {
            resolvedTxOut = provided
        } else if let mapped = uTxOutMap.get(txHashBuf: txHashBuf, txOutNum: txOutNum) {
            resolvedTxOut = mapped
        } else {
            throw TxBuilderError.missingPrevOut(txid: txHashBuf.hex, vout: txOutNum)
        }

        guard let subScript = Script(data: resolvedTxOut.lockingScript) else {
            throw TxBuilderError.malformedLockingScript(nIn: nIn)
        }

        let sig = getSig(privateKey: privateKey, sighashType: sighashType, nIn: nIn, subScript: subScript, signatureVersion: signatureVersion)

        fillSig(nIn: nIn, nScriptChunk: scriptChunk, sig: sig, sighashType: sighashType, publicKey: privateKey.publicKey)

        return self
    }

    mutating func fillSig(nIn: Int, nScriptChunk: Int, sig: Data, sighashType: SighashType, publicKey: PublicKey) {
        transaction.fillSig(nIn: nIn, nScriptChunk: nScriptChunk, sig: sig, sighashType: sighashType, publicKey: publicKey)
    }

}
