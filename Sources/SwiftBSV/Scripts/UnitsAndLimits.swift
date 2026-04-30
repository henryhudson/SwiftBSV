//
//  UnitsAndLimits.swift
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

import Foundation

// P2SH BIP16 didn't become active until Apr 1 2012. All txs before this
// timestamp should not be verified with P2SH rule.
//
// Note (BSV): Genesis (Feb 2020) disabled new P2SH outputs at consensus
// — they are non-standard. Existing P2SH UTXOs from before Genesis remain
// spendable, hence the BIP16 timestamp guard is still meaningful for
// historical-tx validation. Do not introduce P2SH outputs in new code.
let BTC_BIP16_TIMESTAMP: UInt32 = 1_333_238_400

// MARK: - Pre-Genesis (BTC) limits — informational only
//
// BSV's Genesis upgrade (Feb 2020) **removed** the script-level caps below.
// Block-size limits remain but per-script caps are now policy, not consensus.
// These constants are retained for reference and for legacy test vectors.
// The runtime values used by `ScriptMachine` come from `ScriptPolicy.bsv`.
//
// Reference: bitcoin-sv consensus/script/limits, BIP-Genesis whitepaper §5.

let BTC_MAX_SCRIPT_SIZE: Int = 10_000             // pre-Genesis only
let BTC_MAX_SCRIPT_ELEMENT_SIZE: Int = 520        // pre-Genesis only
let BTC_MAX_OPS_PER_SCRIPT: Int = 201             // pre-Genesis only
let BTC_MAX_KEYS_FOR_CHECKMULTISIG: Int = 20      // pre-Genesis only

// MARK: - Other consensus constants

let BTC_LOCKTIME_THRESHOLD: UInt32 = 500_000_000

// MARK: - Script execution policy

/// Per-execution policy for `ScriptMachine`. Consensus on BSV post-Genesis
/// is essentially "any script that fits in a block is fine"; everything below
/// is policy that miners/clients pick. Choose `.bsv` for modern BSV traffic,
/// `.legacy` to replay historical pre-Genesis transactions or to validate
/// against the old test vectors.
public struct ScriptPolicy: Sendable {
    /// Maximum total script byte length.
    public let maxScriptSize: Int
    /// Maximum size of a single pushed data element.
    public let maxElementSize: Int
    /// Maximum number of executable opcodes per script (excluding pushes
    /// and OP_<N>).
    public let maxOpsPerScript: Int
    /// Maximum number of pubkeys allowed in OP_CHECKMULTISIG.
    public let maxKeysForCheckMultisig: Int
    /// Whether to evaluate the BIP16 P2SH redeem-script branch. P2SH is
    /// non-standard on BSV post-Genesis but remains valid for historical
    /// UTXOs.
    public let verifyP2SH: Bool

    public init(maxScriptSize: Int,
                maxElementSize: Int,
                maxOpsPerScript: Int,
                maxKeysForCheckMultisig: Int,
                verifyP2SH: Bool) {
        self.maxScriptSize = maxScriptSize
        self.maxElementSize = maxElementSize
        self.maxOpsPerScript = maxOpsPerScript
        self.maxKeysForCheckMultisig = maxKeysForCheckMultisig
        self.verifyP2SH = verifyP2SH
    }

    /// Pre-Genesis Bitcoin limits. Use for historical-tx replay.
    public static let legacy = ScriptPolicy(
        maxScriptSize: BTC_MAX_SCRIPT_SIZE,
        maxElementSize: BTC_MAX_SCRIPT_ELEMENT_SIZE,
        maxOpsPerScript: BTC_MAX_OPS_PER_SCRIPT,
        maxKeysForCheckMultisig: BTC_MAX_KEYS_FOR_CHECKMULTISIG,
        verifyP2SH: true
    )

    /// BSV post-Genesis defaults. Caps are intentionally large — chosen to
    /// be permissive of any reasonable on-chain script while still preventing
    /// runaway resource use by malformed inputs. They are not consensus.
    public static let bsv = ScriptPolicy(
        maxScriptSize: 1_000_000_000,        // 1 GB; well under block size
        maxElementSize: 1_000_000_000,       // 1 GB; matches above
        maxOpsPerScript: Int.max,            // unbounded by consensus
        maxKeysForCheckMultisig: Int.max,    // unbounded by consensus
        verifyP2SH: false                    // P2SH non-standard on BSV
    )

    /// Default for new `ScriptExecutionContext` instances. Defaults to BSV.
    public static let `default` = ScriptPolicy.bsv
}
