//
//  Mnemonic.swift
//  WalletKit
//
//  Created by yuzushioh on 2018/02/11.
//  Copyright © 2018 yuzushioh. All rights reserved.
//

import Foundation
import CommonCrypto

public typealias Mnemonic = Bip39

// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
/**
 * Bip39: Mnemonic Seeds
 * =====================
 *
 * Bip39 is a way to turn random entropy into a mnemonic (a string of words
 * from a wordlist), and then that mnemonic into a seed. The seed can then be
 * used in Bip32 to derive hierarchical deterministic keys. It does not go the
 * other way around (i.e., you cannot turn a seed into a mnemonic).
 *
 */
public final class Bip39 {
    public enum Strength: Int {
        case normal = 128
        case high = 256
    }
    
    public static func create(strength: Strength = .high, language: WordList = .english) -> String {
        let byteCount = strength.rawValue / 8
        let bytes = Data.randomBytes(length: byteCount)
        return create(entropy: bytes, language: language)
    }
    
    public static func create(entropy: Data, language: WordList = .english) -> String {
        let entropybits = String(entropy.flatMap { ("00000000" + String($0, radix: 2)).suffix(8) })
        let hashBits = String(entropy.sha256().flatMap { ("00000000" + String($0, radix: 2)).suffix(8) })
        let checkSum = String(hashBits.prefix((entropy.count * 8) / 32))
        
        let words = language.words
        let concatenatedBits = entropybits + checkSum
        
        var mnemonic: [String] = []
        for index in 0..<(concatenatedBits.count / 11) {
            let startIndex = concatenatedBits.index(concatenatedBits.startIndex, offsetBy: index * 11)
            let endIndex = concatenatedBits.index(startIndex, offsetBy: 11)
            let wordIndex = Int(strtoul(String(concatenatedBits[startIndex..<endIndex]), nil, 2))
            mnemonic.append(String(words[wordIndex]))
        }
        
        return mnemonic.joined(separator: " ")
    }
    
    /// Validate a BIP-39 mnemonic. Returns `true` only when:
    /// 1. Word count is one of 12 / 15 / 18 / 21 / 24
    /// 2. Every word is in the supplied wordlist
    /// 3. The trailing checksum bits match SHA-256(entropy).prefix(checksumBits)
    ///
    /// Without this check, a phrase with a single mistyped (but valid)
    /// word silently produces a different-but-plausible seed — losing
    /// access to funds with no error surface. Always validate before
    /// `createSeed(mnemonic:)`.
    public static func validate(mnemonic: String, language: WordList = .english) -> Bool {
        let words = mnemonic
            .decomposedStringWithCompatibilityMapping
            .split(separator: " ")
            .map(String.init)

        // Allowed word counts per BIP-39: 12, 15, 18, 21, 24
        guard [12, 15, 18, 21, 24].contains(words.count) else { return false }

        let wordlist = language.words
        // Build a single dictionary lookup so word validation stays linear
        // in mnemonic length (rather than O(words × wordlist)).
        let wordIndex: [String: Int] = {
            var dict = [String: Int]()
            dict.reserveCapacity(wordlist.count)
            for (i, w) in wordlist.enumerated() { dict[String(w)] = i }
            return dict
        }()

        var bits = ""
        for word in words {
            guard let idx = wordIndex[word] else { return false }
            // 11 bits per word, big-endian.
            bits += String(repeating: "0", count: 11 - String(idx, radix: 2).count) + String(idx, radix: 2)
        }

        let totalBits = words.count * 11
        let checksumBits = totalBits / 33
        let entropyBits = totalBits - checksumBits

        let entropyBitsString = String(bits.prefix(entropyBits))
        let checksumString = String(bits.suffix(checksumBits))

        // Pack entropy bits into bytes.
        var entropyBytes = [UInt8]()
        var i = entropyBitsString.startIndex
        while i < entropyBitsString.endIndex {
            let byteEnd = entropyBitsString.index(i, offsetBy: 8, limitedBy: entropyBitsString.endIndex) ?? entropyBitsString.endIndex
            let byteString = String(entropyBitsString[i..<byteEnd])
            guard let byte = UInt8(byteString, radix: 2) else { return false }
            entropyBytes.append(byte)
            i = byteEnd
        }

        let hashBits = String(Data(entropyBytes).sha256()
            .flatMap { ("00000000" + String($0, radix: 2)).suffix(8) })
        let expectedChecksum = String(hashBits.prefix(checksumBits))

        return checksumString == expectedChecksum
    }

    public static func createSeed(mnemonic: String, withPassphrase passphrase: String = "") -> Data {
        let password = mnemonic.decomposedStringWithCompatibilityMapping

        guard let salt = ("mnemonic" + passphrase).decomposedStringWithCompatibilityMapping.data(using: .utf8) else {
            fatalError("Nomalizing salt failed in \(self)")
        }

        return pbkdf2SHA512(password: password, salt: salt, keyByteCount: 64, rounds: 2048)!
    }

    static func pbkdf2SHA512(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
        return pbkdf2(hash:CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512), password:password, salt:salt, keyByteCount:keyByteCount, rounds:rounds)
    }

    static func pbkdf2(hash: CCPBKDFAlgorithm, password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
        let passwordData = password.data(using:String.Encoding.utf8)!
        let derivedKeyData = Data(repeating: 0, count: keyByteCount)

        var copy = derivedKeyData
        
        // Use the modern Raw-buffer-pointer API. The deprecated
        // typed-buffer-pointer overloads (UnsafeMutableBytes returning a
        // typed pointer, etc.) are the variants the compiler now warns on.
        // CCKeyDerivationPBKDF expects raw byte pointers, which the new
        // closures provide directly via `.baseAddress`.
        let derivationStatus = copy.withUnsafeMutableBytes { (derivedKeyBytes: UnsafeMutableRawBufferPointer) in
            salt.withUnsafeBytes { (saltBytes: UnsafeRawBufferPointer) in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password, passwordData.count,
                    saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                    hash,
                    UInt32(rounds),
                    derivedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), derivedKeyData.count
                )
            }
        }
        if (derivationStatus != 0) {
            print("Error: \(derivationStatus)")
            return nil;
        }

        return copy
    }
}

