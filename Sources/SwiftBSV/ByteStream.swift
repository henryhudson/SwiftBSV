//
//  ByteStream.swift
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

/// Raised when a transaction cannot be deserialized — a truncated or
/// structurally invalid byte stream, rather than a crash.
public enum DeserializationError: Error, Equatable {
    /// A read ran past the end of the byte stream — truncated input.
    case unexpectedEndOfStream
    /// A length/count field declares a value too large to represent —
    /// the stream is structurally invalid, not merely short.
    case malformedData
}

class ByteStream {
    let data: Data
    private var offset = 0

    var availableBytes: Int {
        return data.count - offset
    }

    init(_ data: Data) {
        self.data = data
    }

    func read<T>(_ type: T.Type) throws -> T {
        let size = MemoryLayout<T>.size
        guard availableBytes >= size else { throw DeserializationError.unexpectedEndOfStream }
        let value = data[offset..<(offset + size)].to(type: type)
        offset += size
        return value
    }

    func read(_ type: VarInt.Type) throws -> VarInt {
        guard availableBytes >= 1 else { throw DeserializationError.unexpectedEndOfStream }
        let len = data[offset..<(offset + 1)].to(type: UInt8.self)
        let length: UInt64
        switch len {
        case 0...252:
            length = UInt64(len); offset += 1
        case 0xfd:
            guard availableBytes >= 3 else { throw DeserializationError.unexpectedEndOfStream }
            offset += 1
            length = UInt64(data[offset..<(offset + 2)].to(type: UInt16.self)); offset += 2
        case 0xfe:
            guard availableBytes >= 5 else { throw DeserializationError.unexpectedEndOfStream }
            offset += 1
            length = UInt64(data[offset..<(offset + 4)].to(type: UInt32.self)); offset += 4
        default: // 0xff
            guard availableBytes >= 9 else { throw DeserializationError.unexpectedEndOfStream }
            offset += 1
            length = UInt64(data[offset..<(offset + 8)].to(type: UInt64.self)); offset += 8
        }
        return VarInt(length)
    }

    func read(_ type: VarString.Type) throws -> VarString {
        let length = try read(VarInt.self).underlyingValue
        guard let size = Int(exactly: length) else { throw DeserializationError.malformedData }
        guard availableBytes >= size else { throw DeserializationError.unexpectedEndOfStream }
        let value = data[offset..<(offset + size)].to(type: String.self)
        offset += size
        return VarString(value)
    }

    func read(_ type: Data.Type, count: Int) throws -> Data {
        guard count >= 0, availableBytes >= count else {
            throw DeserializationError.unexpectedEndOfStream
        }
        let value = data[offset..<(offset + count)]
        offset += count
        return Data(value)
    }
}
