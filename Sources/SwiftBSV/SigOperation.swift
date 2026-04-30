//
//  SigOperation.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-18.
//  Copyright © 2020 wtsnz. All rights reserved.
//

import Foundation

public struct SigOperation {

    public enum OperationType {
        case sig
        case pubkey
    }

    var nScriptChunk: UInt32
    var type: OperationType
    var addressString: String
    var nHashType: SighashType
}

/// Value-type map of pending signature/pubkey insertions, keyed by
/// `<txHashBuf.hex>:<txOutNum>`. See `TxOutMap` for the same rationale —
/// no reference-semantics requirement here, so a `struct` is the right
/// choice and is also a prerequisite for making `TxBuilder` a struct
/// (a struct holding a class field has bizarre value semantics).
struct SigOperations {

    private var map = [String: [SigOperation]]()

    /// Set an address to in the map for use with single-sig.
    /// - Parameters:
    ///   - txHashBuf: The hash of a transsaction. Note that this is *not* the reversed transaction id, but is the raw hash.
    ///   - txOutNum: The output number, a.k.a. the "vout".
    ///   - nScriptChunk: The index of the chunk of the script where we are going to place the signature.
    ///   - type: the sig operation type (sig, or pubkey)
    ///   - addressString: The addressStr coresponding to this (txHashBuf, txOutNum, nScriptChunk) where we are going to sign and insert the signature or public key.
    ///   - nHashType: Usually = Sig.SIGHASH_ALL | Sig.SIGHASH_FORKID
    mutating func setOne(txHashBuf: Data, txOutNum: UInt32, nScriptChunk: UInt32, type: SigOperation.OperationType, addressString: String, nHashType: SighashType = SighashType.BSV.ALL) {
        let label = txHashBuf.hex + ":" + String(txOutNum)
        let sigOperation = SigOperation(nScriptChunk: nScriptChunk, type: type, addressString: addressString, nHashType: nHashType)
        map[label] = [sigOperation]
    }

    /// Set a bunch of addresses for signing an input such as for use with multi-sig.
    mutating func setMany(txHashBuf: Data, txOutNum: UInt32, operations: [SigOperation]) {
        let label = txHashBuf.hex + ":" + String(txOutNum)
        map[label] = operations
    }

    mutating func addOne(txHashBuf: Data, txOutNum: UInt32, nScriptChunk: UInt32, type: SigOperation.OperationType = .sig, addressString: String, nHashType: SighashType = SighashType.BSV.ALL) {
        // Single dictionary subscript with `default: []` collapses the
        // get / mutate / set dance into the canonical Swift idiom — no
        // intermediate state where another caller could observe a
        // partially-built array.
        let label = txHashBuf.hex + ":" + String(txOutNum)
        map[label, default: []].append(
            SigOperation(nScriptChunk: nScriptChunk, type: type, addressString: addressString, nHashType: nHashType)
        )
    }

    /// Get the operations from the map
    /// - Parameters:
    ///   - txHashBuf: The hash of a transction. Note that this is *not* the reversed transaction id, but is the raw hash.
    ///   - txOutNum: The output number, a.k.a. the "vout".
    /// - Returns: The array of SigOperations that will be applied to the transaction when signing.
    func get(txHashBuf: Data, txOutNum: UInt32) -> [SigOperation]? {
        let label = txHashBuf.hex + ":" + String(txOutNum)
        return map[label]
    }

}
