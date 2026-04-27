//
//  SigOperationsTests.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-22.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation
import XCTest
@testable import SwiftBSV

class SigOperationsTests: XCTestCase {

    func testSighashType() {
        var sighashType = SighashType(i: 0x00000001)
        XCTAssertEqual(sighashType.isAll, true)
        XCTAssertEqual(sighashType.isNone, false)
        XCTAssertEqual(sighashType.isSingle, false)
        XCTAssertEqual(sighashType.hasAnyoneCanPay, false)
        XCTAssertEqual(sighashType.hasForkId, false)

        sighashType = SighashType(i: 0x02)
        XCTAssertEqual(sighashType.isAll, false)
        XCTAssertEqual(sighashType.isNone, true)
        XCTAssertEqual(sighashType.isSingle, false)
        XCTAssertEqual(sighashType.hasAnyoneCanPay, false)
        XCTAssertEqual(sighashType.hasForkId, false)

        sighashType = SighashType(i: 0x03)
        XCTAssertEqual(sighashType.isAll, false)
        XCTAssertEqual(sighashType.isNone, false)
        XCTAssertEqual(sighashType.isSingle, true)
        XCTAssertEqual(sighashType.hasAnyoneCanPay, false)
        XCTAssertEqual(sighashType.hasForkId, false)

        sighashType = SighashType(i: 0x3 + 0x40)
        XCTAssertEqual(sighashType.isAll, false)
        XCTAssertEqual(sighashType.isNone, false)
        XCTAssertEqual(sighashType.isSingle, true)
        XCTAssertEqual(sighashType.hasAnyoneCanPay, false)
        XCTAssertEqual(sighashType.hasForkId, true)

        sighashType = SighashType(i: 0x3 + 0x2)
        XCTAssertEqual(sighashType.isAll, true)
        XCTAssertEqual(sighashType.isNone, false)
        XCTAssertEqual(sighashType.isSingle, false)
        XCTAssertEqual(sighashType.hasAnyoneCanPay, false)
        XCTAssertEqual(sighashType.hasForkId, false)

        sighashType = SighashType(i: -1835000116)
        XCTAssertEqual(sighashType.isAll, true)
        XCTAssertEqual(sighashType.isNone, false)
        XCTAssertEqual(sighashType.isSingle, false)
        XCTAssertEqual(sighashType.hasAnyoneCanPay, true)
        XCTAssertEqual(sighashType.hasForkId, true)

        sighashType = SighashType(i: -1835000116)
        XCTAssertEqual(sighashType.isAll, true)
        XCTAssertEqual(sighashType.isNone, false)
        XCTAssertEqual(sighashType.isSingle, false)
        XCTAssertEqual(sighashType.hasAnyoneCanPay, true)
        XCTAssertEqual(sighashType.hasForkId, true)
    }

//    let txHashBuf = Data(repeating: 0x01, count: 32)
//    let txOutNum: UInt32 = 5
//    let nScriptChunk: UInt32 = 0
//    let privKey = PrivateKey(wif: "L3uCzo4TtW3FX5b5L9S5dKDu21ypeRofiiNnVuYnxGs5YRQrUFP2")!
//    lazy var pubKey = privKey.publicKey
//    lazy var addressStr = pubKey.address.toString()
//    let sigHashType = BSVSighashType.ALL

//    func testSetOne() {
//
//        let sigOperations = SigOperations()
//        sigOperations.setOne(txHashBuf: txHashBuf, txOutNum: txOutNum, nScriptChunk: nScriptChunk, type: .sig, addressString: addressStr)
//
//        let operations = sigOperations.get(txHashBuf: txHashBuf, txOutNum: txOutNum)
//
//        XCTAssertEqual(operations?.count, 1)
//
//        if let op = operations?.first {
//
//            XCTAssertEqual(op.addressString, addressStr)
//            XCTAssertEqual(op.nScriptChunk, nScriptChunk)
//            XCTAssertEqual(op.nHashType.rawValue, BSVSighashType.ALL.rawValue)
//
//        }
//    }

    func testCrypto() {

        let privateKey = PrivateKey(wif: "cT5XuiE2xs65HnMMgKRd4vkbNukYqqtWUzL5SMRPPE4VvT3FT3xn", network: .testnet)!
        let publicKey = privateKey.publicKey

        XCTAssertEqual(privateKey.toWif(), "cT5XuiE2xs65HnMMgKRd4vkbNukYqqtWUzL5SMRPPE4VvT3FT3xn")
        XCTAssertEqual(privateKey.toWifData().hex, "efa404f0ddada148bed16adb2b8b0be3736cc890f2f58396b6cf9df2548cd6561101")

        XCTAssertEqual(privateKey.bn.asString(radix: 10), "74188036951471619320559862509596633229069560545164083305989367417300487394833")
        XCTAssertEqual(privateKey.bn.asString(radix: 16), "a404f0ddada148bed16adb2b8b0be3736cc890f2f58396b6cf9df2548cd65611")

        let address = Address(privateKey, network: .testnet)

        XCTAssertEqual(address.toString(), "mpcd4bwYbTiqqZZ2s26eyv1MZTpnbMW6R7")

        print("privateKeyWif: " + privateKey.toWif())

        print("privateKeyData: " + privateKey.data.hex)
        print("privateKeyData: " + privateKey.toWifData().hex)
        print("publicKeyBuffer: " + publicKey.toBuffer().hex)
        print("publicKeyDER: " + publicKey.toDer().hex)
        print("pubKey Address: " + address.toString())

        let message = Data(Data(hex: "1972021cb452364bcf77c26ffabed86f4594c8605d83955ad14aa32093c54ff0"))


        // Foundation's Data.bytes now returns RawSpan in Swift 6+; secp256k1 wants [UInt8].
        // [UInt8](data) materializes a byte array unambiguously across toolchain versions.
        let test1 = try! Secp256k1.signCompact(msg: [UInt8](message), with: [UInt8](privateKey.data), nonceFunction: Secp256k1.NonceFunction.rfc6979)

        let test = try! Secp256k1.sign(msg: [UInt8](message), with: [UInt8](privateKey.data), nonceFunction: Secp256k1.NonceFunction.rfc6979)

        let sig = Crypto.sign(message, privateKey: privateKey)

        for i in 0..<5 {
            let sig = Crypto.sign(message, privateKey: privateKey)
            print("sig    : " + sig.hex)
        }

        print("message: " + message.hex)
        print("sig    : " + sig.hex)


        // Crypto.sign emits a DER-encoded signature, so verifySignature
        // (DER) is the correct verifier — verifySignatureCompact expects
        // the 65-byte recoverable-signature format from Crypto.signCompact.
        let check = Crypto.verifySignature(sig, message: message, publicKey: publicKey)

        XCTAssertEqual(check, true)


        ///304402200cf50892c61c619fbb60be74a37731e737fc77397b95497956e41efd5bf6dfdc0220044f6c43098ef3f24e0a8c3e9b7632b36b4df9e0410c06ca42b65807888adca941
    }

    func test2() {

        let privKey = PrivateKey(data: Data(hex: "97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a"))
        let pubKey = privKey.publicKey

        print(privKey.data.hex)
        print(pubKey.toBuffer().hex)
        print(pubKey.toDer().hex)

        let msg = "Message for signing"
        
        let msgHash = Crypto.sha3keccak256(data: msg.data(using: .utf8)!)
        let sig = Crypto.sign(msgHash, privateKey: privKey)

        print(msg)
        print(msgHash.hex)
        print(sig.hex)

        let check = Crypto.verifySignature(sig, message: msgHash, publicKey: pubKey)

        XCTAssert(check == true)
    }

    func testKnownData() {

        let privKey = PrivateKey()
        let pubKey = privKey.publicKey

        print(privKey.data.hex)
        print(pubKey.toBuffer().hex)
        print(pubKey.toDer().hex)

        let msg = "Message for signing"

        let msgHash = Crypto.sha3keccak256(data: msg.data(using: .utf8)!)
        let sig = Crypto.sign(msgHash, privateKey: privKey)

        print(msg)
        print(msgHash.hex)
        print(sig.hex)

//        let pub = Crypto.computePublicKey(fromPrivateKey: privKey.data, compressed: false)

        let check = Crypto.verifySignature(sig, message: msgHash, publicKey: privKey.publicKey)

        XCTAssert(check == true)
    }

    // TODO: Add more tests for the other methods

    func testdsfdf() {

        let data = "Satoshi Nakamoto"
        // CryptoSwift's String.sha256() returns a hex string, not raw bytes.
        // [UInt8](hex:) parses the hex back to the 32 actual hash bytes.
        let hash = data.sha256()

        let key = Data(hex: "8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15")

        _ = try! Secp256k1.sign(msg: [UInt8](hex: hash), with: [UInt8](key), nonceFunction: Secp256k1.NonceFunction.rfc6979)

    }

}
