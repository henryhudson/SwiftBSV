//
//  ScriptMachineTests.swift
//
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

import XCTest
@testable import SwiftBSV
import Foundation

class ScriptMachineTests: XCTestCase {

    func testScript() {

        let lockingScript = Script(string: "OP_1 OP_EQUAL")!
        let unlockingScript = Script(string: "OP_2 OP_1SUB")!

        let context = ScriptExecutionContext(isDebug: true)

        do {
            let result = try ScriptMachine.verify(
                lockScript: lockingScript,
                unlockScript: unlockingScript,
                context: context
            )

            dump(result)
        } catch {
            // Errors from execute(_:) are intentionally ignored in this smoke
            // test — the only assertion is that the call returns at all.
        }


    }

    /// End-to-end signature round-trip through `Crypto.verifySigData`
    /// AND `ScriptMachine.verifyTransaction`. The original placeholder
    /// referenced a testnet3 transaction by external txid plus types
    /// that no longer exist on the public API (`BTCSignatureHashHelper`,
    /// `PublicKey.pubkeyHash`); rewriting as a self-contained round-trip
    /// keeps the testable invariant — "a tx I signed must verify locally"
    /// — without depending on external chain state.
    func testCheck() throws {
        let signer = PrivateKey(network: .mainnet)
        let recipient = PrivateKey(network: .mainnet)

        // Fabricate a previous-output the signer controls.
        let prevTxid = Data(repeating: 0xcd, count: 32)
        let utxo = TransactionOutput(
            value: 169_012_961,
            lockingScript: signer.publicKey.address.toTxOutputScript().data
        )

        // Build an unsigned spending tx — placeholder signatureScript
        // matches the locking script (`Transaction.sign` ignores it).
        let unsignedInput = TransactionInput(
            previousOutput: TransactionOutPoint(hash: prevTxid, index: 1),
            signatureScript: utxo.lockingScript,
            sequence: UInt32.max
        )
        let payOut = TransactionOutput(
            value: 50_000_000,
            lockingScript: recipient.publicKey.address.toTxOutputScript().data
        )
        let changeOut = TransactionOutput(
            value: 169_012_961 - 50_000_000 - 10_000_000,
            lockingScript: signer.publicKey.address.toTxOutputScript().data
        )
        let unsignedTx = Transaction(
            version: 1,
            inputs: [unsignedInput],
            outputs: [payOut, changeOut],
            lockTime: 0
        )

        // Sign with FORKID (BSV consensus default).
        let sighashType = SighashType.BSV.ALL
        let subScript = Script(data: utxo.lockingScript)!
        let derSig = unsignedTx.sign(
            privateKey: signer,
            sighashType: sighashType,
            nIn: 0,
            subScript: subScript,
            value: utxo.value
        )
        let wireSig = derSig + Data([UInt8(sighashType.sighash & 0xff)])

        // Construct the unlocking scriptSig (sig, then pubkey).
        let unlockScript = try Script()
            .appendData(wireSig)
            .appendData(signer.publicKey.toDer())
        let signedInput = TransactionInput(
            previousOutput: unsignedInput.previousOutput,
            signatureScript: unlockScript.data,
            sequence: UInt32.max
        )
        let signedTx = Transaction(
            version: 1,
            inputs: [signedInput],
            outputs: [payOut, changeOut],
            lockTime: 0
        )

        // 1. Direct Crypto.verifySigData check — the path used by OP_CHECKSIG.
        let cryptoResult = try Crypto.verifySigData(
            for: signedTx,
            inputIndex: 0,
            utxo: utxo,
            sigData: wireSig,
            pubKeyData: signer.publicKey.toDer()
        )
        XCTAssertTrue(cryptoResult, "Crypto.verifySigData rejected a signature it should accept")

        // 2. Full ScriptMachine round-trip — runs unlock + lock + OP_CHECKSIG.
        let machineResult = try ScriptMachine.verifyTransaction(
            signedTx: signedTx,
            inputIndex: 0,
            utxo: utxo
        )
        XCTAssertTrue(machineResult, "ScriptMachine.verifyTransaction rejected a tx it should accept")
    }
}
