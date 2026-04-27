//
//  DataConvertable.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-18.
//  Copyright © 2020 wtsnz. All rights reserved.
//

import Foundation

protocol DataConvertable {
    static func +(lhs: Data, rhs: Self) -> Data
    static func +=(lhs: inout Data, rhs: Self)
}

extension DataConvertable {
    static func +(lhs: Data, rhs: Self) -> Data {
        // Same dangling-pointer fix as Data+Script.swift's `BinaryConvertible.+`
        // and `Data.init(from:)` — the previous form
        // `UnsafeBufferPointer(start: &value, count: 1)` produced a buffer
        // whose lifetime ended at the call boundary, leaving a dangling
        // pointer that the compiler now warns on. `withUnsafeBytes(of:)`
        // bounds the buffer's lifetime to the closure, and `Data($0)` copies
        // before returning.
        var value = rhs
        let data = withUnsafeBytes(of: &value) { Data($0) }
        return lhs + data
    }

    static func +=(lhs: inout Data, rhs: Self) {
        lhs = lhs + rhs
    }
}

extension UInt8: DataConvertable {}
extension UInt32: DataConvertable {}

