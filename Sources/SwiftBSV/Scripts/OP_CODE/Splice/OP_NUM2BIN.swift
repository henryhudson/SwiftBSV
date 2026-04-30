//
//  OP_NUM2BIN.swift
//
//  BSV consensus: convert a numeric value `a` to a fixed-length byte sequence
//  of length `b`. Mirrors the bitcoin-sv reference implementation.
//
//  Stack: ( a b -- out )
//
//  Re-encodes `a` (a script-num buffer) into exactly `b` bytes by stripping
//  its sign bit, zero-padding to `b - 1` bytes, then re-attaching the sign
//  bit on the new most-significant byte. Fails if `a` does not fit in `b`
//  bytes after sign-stripping.
//

import Foundation

public struct OpNum2Bin: OpCodeProtocol {
    public var value: UInt8 { return 0x80 }
    public var name: String { return "OP_NUM2BIN" }

    public func mainProcess(_ context: ScriptExecutionContext) throws {
        try context.assertStackHeightGreaterThanOrEqual(2)

        // size is on top of the stack; the source bin is below it.
        let sizeData = context.stack.removeLast()
        var bin = context.stack.removeLast()

        // size must decode as a non-negative script number; the upper bound
        // is the per-element push limit from `pushToStack`, so we delegate
        // that check to the final push instead of duplicating the constant
        // here.
        guard let size = BInt(fromScriptNumBuffer: sizeData).asInt32(), size >= 0 else {
            throw OpCodeExecutionError.error("OP_NUM2BIN: size must be a non-negative script number")
        }

        // Empty input is treated as zero — produce `size` zero bytes.
        if bin.isEmpty {
            try context.pushToStack(Data(repeating: 0, count: Int(size)))
            return
        }

        // Strip the sign bit off the existing most-significant byte.
        let signByteIndex = bin.count - 1
        let signBit: UInt8 = bin[signByteIndex] & 0x80
        bin[signByteIndex] &= 0x7f

        // After stripping, drop any leading zero bytes from the high end so
        // we know the true minimum width — needed to detect "doesn't fit".
        while bin.count > 1 && bin.last == 0x00 {
            bin.removeLast()
        }

        // If the only byte left is zero, the input was effectively zero —
        // collapse to an empty buffer so `size` zero-padding produces the
        // canonical encoding.
        if bin.count == 1 && bin[0] == 0x00 {
            bin = Data()
        }

        guard bin.count <= Int(size) else {
            throw OpCodeExecutionError.error("OP_NUM2BIN: input does not fit in \(size) bytes")
        }

        // Pad to `size - 1` bytes, then place the sign bit on the new MSB.
        var out = bin
        if out.count < Int(size) {
            out.append(Data(repeating: 0, count: Int(size) - out.count))
        }
        if size > 0 {
            out[Int(size) - 1] |= signBit
        }

        try context.pushToStack(out)
    }
}
