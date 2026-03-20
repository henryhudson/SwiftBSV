//
//  ScriptFactory.swift
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

public struct ScriptFactory {
    // Basic
    public struct Standard {}
    public struct LockTime {}
    public struct MultiSig {}
    public struct OpReturn {}
    public struct Condition {}
    public struct PushDrop {}

    // Contract
    public struct HashedTimeLockedContract {}
}

// MARK: - Standard
public extension ScriptFactory.Standard {
    static func buildP2PK(publickey: PublicKey) -> Script? {
        return try? Script()
            .appendData(publickey.toDer())
            .append(.OP_CHECKSIG)
    }

    /// Build a P2PKH locking script from an Address.
    /// Format: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    static func buildP2PKH(address: Address) -> Script {
        return Script.buildPublicKeyHashOut(pubKeyHash: address.hashBuffer)
    }

    /// Build a P2PKH locking script from a public key.
    static func buildP2PKH(publicKey: PublicKey) -> Script {
        return Script.buildPublicKeyHashOut(pubKeyHash: publicKey.address.hashBuffer)
    }

    static func buildP2SH(script: Script) -> Script {
        return script.toP2SH()
    }

    static func buildMultiSig(publicKeys: [PublicKey]) -> Script? {
        return Script(publicKeys: publicKeys, signaturesRequired: UInt(publicKeys.count))
    }
    static func buildMultiSig(publicKeys: [PublicKey], signaturesRequired: UInt) -> Script? {
        return Script(publicKeys: publicKeys, signaturesRequired: signaturesRequired)
    }
}

// MARK: - LockTime
public extension ScriptFactory.LockTime {
    // Base
    static func build(script: Script, lockDate: Date) -> Script? {
        return try? Script()
            .appendData(lockDate.bigNumData)
            .append(.OP_CHECKLOCKTIMEVERIFY)
            .append(.OP_DROP)
            .appendScript(script)
    }

    static func build(script: Script, lockIntervalSinceNow: TimeInterval) -> Script? {
        let lockDate = Date(timeIntervalSinceNow: lockIntervalSinceNow)
        return build(script: script, lockDate: lockDate)
    }

    // P2PKH + LockTime
//    static func build(address: Address, lockIntervalSinceNow: TimeInterval) -> Script? {
//        guard let p2pkh = Script(address: address) else {
//            return nil
//        }
//        let lockDate = Date(timeIntervalSinceNow: lockIntervalSinceNow)
//        return build(script: p2pkh, lockDate: lockDate)
//    }
//
//    static func build(address: Address, lockDate: Date) -> Script? {
//        guard let p2pkh = Script(address: address) else {
//            return nil
//        }
//        return build(script: p2pkh, lockDate: lockDate)
//    }
}

// MARK: - OpReturn
public extension ScriptFactory.OpReturn {
    /// Build an OP_RETURN script from a text string.
    /// Format: OP_RETURN <utf8 data>
    static func build(text: String) -> Script? {
        let MAX_OP_RETURN_DATA_SIZE: Int = 220
        guard let data = text.data(using: .utf8), data.count <= MAX_OP_RETURN_DATA_SIZE else {
            return nil
        }
        return try? Script()
            .append(.OP_RETURN)
            .appendData(data)
    }

    /// Build a safe (unspendable) OP_RETURN script from raw data.
    /// Format: OP_FALSE OP_RETURN <data>
    /// The OP_FALSE prefix makes this provably unspendable (BIP 141 convention).
    static func buildSafe(data: Data) -> Script? {
        return try? Script()
            .append(.OP_0)
            .append(.OP_RETURN)
            .appendData(data)
    }

    /// Build a safe OP_RETURN with multiple data pushes.
    /// Format: OP_FALSE OP_RETURN <data1> <data2> ...
    /// Used by protocols like B://, MAP, and 1Sat Ordinals.
    static func buildSafe(pushes: [Data]) -> Script? {
        guard !pushes.isEmpty else { return nil }
        var script = try? Script()
            .append(.OP_0)
            .append(.OP_RETURN)
        for push in pushes {
            script = try? script?.appendData(push)
        }
        return script
    }

    /// Build a safe OP_RETURN from a text string.
    /// Format: OP_FALSE OP_RETURN <utf8 data>
    static func buildSafe(text: String) -> Script? {
        guard let data = text.data(using: .utf8) else { return nil }
        return buildSafe(data: data)
    }
}

// MARK: - PushDrop
public extension ScriptFactory.PushDrop {
    /// Build a PushDrop script (1Sat Ordinals / token protocols).
    /// Format: <data1> <data2> ... OP_DROP ... OP_DROP <lockingScript>
    /// The data pushes are dropped during execution, leaving only the locking script.
    /// Used to attach arbitrary data to a UTXO while preserving spendability.
    static func build(pushes: [Data], lockingScript: Script) -> Script? {
        guard !pushes.isEmpty else { return nil }
        var script = Script()
        do {
            for push in pushes {
                try script.appendData(push)
            }
            // Drop all but the last push, which serves as part of the execution
            for _ in 0..<pushes.count {
                try script.append(.OP_DROP)
            }
            try script.appendScript(lockingScript)
            return script
        } catch {
            return nil
        }
    }
}

// MARK: - Condition
public extension ScriptFactory.Condition {
    static func build(scripts: [Script]) -> Script? {

        guard !scripts.isEmpty else {
            return nil
        }
        guard scripts.count > 1 else {
            return scripts[0]
        }

        var scripts: [Script] = scripts

        while scripts.count > 1 {
            var newScripts: [Script] = []
            while !scripts.isEmpty {
                let script = Script()
                do {
                    if scripts.count == 1 {
                        try script
                            .append(.OP_DROP)
                            .appendScript(scripts.removeFirst())
                    } else {
                        try script
                            .append(.OP_IF)
                            .appendScript(scripts.removeFirst())
                            .append(.OP_ELSE)
                            .appendScript(scripts.removeFirst())
                            .append(.OP_ENDIF)
                    }
                } catch {
                    return nil
                }
                newScripts.append(script)
            }
            scripts = newScripts
        }

        return scripts[0]
    }
}

// MARK: - HTLC
/*
 OP_IF
    [HASHOP] <digest> OP_EQUALVERIFY OP_DUP OP_HASH160 <recipient pubkey hash>
 OP_ELSE
    <num> [TIMEOUTOP] OP_DROP OP_DUP OP_HASH160 <sender pubkey hash>
 OP_ENDIF
 OP_EQUALVERIFYs
 OP_CHECKSIG
*/
public extension ScriptFactory.HashedTimeLockedContract {
    // Base
//    static func build(recipient: Address, sender: Address, lockDate: Date, hash: Data, hashOp: HashOperator) -> Script? {
//        guard hash.count == hashOp.hashSize else {
//            return nil
//        }
//
//        return try? Script()
//            .append(.OP_IF)
//                .append(hashOp.opcode)
//                .appendData(hash)
//                .append(.OP_EQUALVERIFY)
//                .append(.OP_DUP)
//                .append(.OP_HASH160)
//                .appendData(recipient.data)
//            .append(.OP_ELSE)
//                .appendData(lockDate.bigNumData)
//                .append(.OP_CHECKLOCKTIMEVERIFY)
//                .append(.OP_DROP)
//                .append(.OP_DUP)
//                .append(.OP_HASH160)
//                .appendData(sender.data)
//            .append(.OP_ENDIF)
//            .append(.OP_EQUALVERIFY)
//            .append(.OP_CHECKSIG)
//    }

    // convenience
//    static func build(recipient: Address, sender: Address, lockIntervalSinceNow: TimeInterval, hash: Data, hashOp: HashOperator) -> Script? {
//        let lockDate = Date(timeIntervalSinceNow: lockIntervalSinceNow)
//        return build(recipient: recipient, sender: sender, lockDate: lockDate, hash: hash, hashOp: hashOp)
//    }
//
//    static func build(recipient: Address, sender: Address, lockIntervalSinceNow: TimeInterval, secret: Data, hashOp: HashOperator) -> Script? {
//        let hash = hashOp.hash(secret)
//        let lockDate = Date(timeIntervalSinceNow: lockIntervalSinceNow)
//        return build(recipient: recipient, sender: sender, lockDate: lockDate, hash: hash, hashOp: hashOp)
//    }
//
//    static func build(recipient: Address, sender: Address, lockDate: Date, secret: Data, hashOp: HashOperator) -> Script? {
//        let hash = hashOp.hash(secret)
//        return build(recipient: recipient, sender: sender, lockDate: lockDate, hash: hash, hashOp: hashOp)
//    }

}

public class HashOperator {
    public static let SHA256: HashOperator = HashOperatorSha256()
    public static let HASH160: HashOperator = HashOperatorHash160()

    public var opcode: OpCode { return .OP_INVALIDOPCODE }
    public var hashSize: Int { return 0 }
    public func hash(_ data: Data) -> Data { return Data() }
    fileprivate init() {}
}

final public class HashOperatorSha256: HashOperator {
    override public var opcode: OpCode { return .OP_SHA256 }
    override public var hashSize: Int { return 32 }

    override public func hash(_ data: Data) -> Data {
        return Crypto.sha256(data)
    }
}

final public class HashOperatorHash160: HashOperator {
    override public var opcode: OpCode { return .OP_HASH160 }
    override public var hashSize: Int { return 20 }

    override public func hash(_ data: Data) -> Data {
        return Crypto.sha256ripemd160(data)
    }
}

// MARK: - Utility Extension
private extension Date {
    var bigNumData: Data {
        let dateUnix: TimeInterval = timeIntervalSince1970
        let bn = BInt(Int32(dateUnix).littleEndian)
//        let bn = BigNumber(Int32(dateUnix).littleEndian)
        return bn.data
    }
}
