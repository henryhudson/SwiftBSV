//
//  Data+Random.swift
//  HDWalletKit
//
//  Created by Pavlo Boiko on 20.08.18.
//  Copyright © 2018 Essentia. All rights reserved.
//

import Foundation
#if canImport(Security)
import Security
#endif

extension Data {

    /// Securely generate random bytes of length.
    static func randomBytes(length: Int) -> Data {
        #if canImport(Security)
        var bytes = Data(count: length)
        _ = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!) }
        return bytes
        #else
        // Linux and Android: the standard library's system generator reads the
        // kernel's cryptographically secure source (getrandom / arc4random_buf).
        return Data(secureRandomBytes(count: length))
        #endif
    }
}

#if !canImport(Security)
/// Bytes from `SystemRandomNumberGenerator`, the platform's secure random source
/// where Apple's `SecRandomCopyBytes` does not exist.
func secureRandomBytes(count: Int) -> [UInt8] {
    var generator = SystemRandomNumberGenerator()
    return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
}
#endif
