//
//  OP_NOPN.swift
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

public struct OpNop1: OpCodeProtocol {
    public var value: UInt8 { return 0xb0 }
    public var name: String { return "OP_NOP1" }

    public func mainProcess(_ context: ScriptExecutionContext) throws {
        // do nothing
    }
}

// Chronicle upgrade: OP_SUBSTR (0xb3) — substring by start index and length
public struct OpNop4: OpCodeProtocol {
    public var value: UInt8 { return 0xb3 }
    public var name: String { return "OP_SUBSTR" }

    // (data start length -- substring)
    public func mainProcess(_ context: ScriptExecutionContext) throws {
        try context.assertStackHeightGreaterThanOrEqual(3)
        let length = try context.number(at: -1)
        let start = try context.number(at: -2)
        let data: Data = context.data(at: -3)
        guard start >= 0 && length >= 0 && Int(start + length) <= data.count else {
            throw OpCodeExecutionError.error("Invalid OP_SUBSTR range")
        }
        context.stack.removeLast(3)
        context.stack.append(Data(data[Int(start)..<Int(start + length)]))
    }
}

// Chronicle upgrade: OP_LEFT (0xb4) — extract leftmost N bytes
public struct OpNop5: OpCodeProtocol {
    public var value: UInt8 { return 0xb4 }
    public var name: String { return "OP_LEFT" }

    // (data n -- left)
    public func mainProcess(_ context: ScriptExecutionContext) throws {
        try context.assertStackHeightGreaterThanOrEqual(2)
        let n = try context.number(at: -1)
        let data: Data = context.data(at: -2)
        guard n >= 0 && Int(n) <= data.count else {
            throw OpCodeExecutionError.error("Invalid OP_LEFT size")
        }
        context.stack.removeLast(2)
        context.stack.append(Data(data.prefix(Int(n))))
    }
}

// Chronicle upgrade: OP_RIGHT (0xb5) — extract rightmost N bytes
public struct OpNop6: OpCodeProtocol {
    public var value: UInt8 { return 0xb5 }
    public var name: String { return "OP_RIGHT" }

    // (data n -- right)
    public func mainProcess(_ context: ScriptExecutionContext) throws {
        try context.assertStackHeightGreaterThanOrEqual(2)
        let n = try context.number(at: -1)
        let data: Data = context.data(at: -2)
        guard n >= 0 && Int(n) <= data.count else {
            throw OpCodeExecutionError.error("Invalid OP_RIGHT size")
        }
        context.stack.removeLast(2)
        context.stack.append(Data(data.suffix(Int(n))))
    }
}

// Chronicle upgrade: OP_LSHIFTNUM (0xb6) — numeric left shift preserving sign
public struct OpNop7: OpCodeProtocol {
    public var value: UInt8 { return 0xb6 }
    public var name: String { return "OP_LSHIFTNUM" }

    // (n shift -- result)
    public func mainProcess(_ context: ScriptExecutionContext) throws {
        try context.assertStackHeightGreaterThanOrEqual(2)
        let shift = try context.number(at: -1)
        let value = try context.number(at: -2)
        guard shift >= 0 else {
            throw OpCodeExecutionError.error("Negative shift in OP_LSHIFTNUM")
        }
        context.stack.removeLast(2)
        let magnitude = abs(value) << shift
        try context.pushToStack(value < 0 ? -magnitude : magnitude)
    }
}

// Chronicle upgrade: OP_RSHIFTNUM (0xb7) — numeric right shift preserving sign
public struct OpNop8: OpCodeProtocol {
    public var value: UInt8 { return 0xb7 }
    public var name: String { return "OP_RSHIFTNUM" }

    // (n shift -- result)
    public func mainProcess(_ context: ScriptExecutionContext) throws {
        try context.assertStackHeightGreaterThanOrEqual(2)
        let shift = try context.number(at: -1)
        let value = try context.number(at: -2)
        guard shift >= 0 else {
            throw OpCodeExecutionError.error("Negative shift in OP_RSHIFTNUM")
        }
        context.stack.removeLast(2)
        let magnitude = abs(value) >> shift
        try context.pushToStack(value < 0 ? -magnitude : magnitude)
    }
}

public struct OpNop9: OpCodeProtocol {
    public var value: UInt8 { return 0xb8 }
    public var name: String { return "OP_NOP9" }

    public func mainProcess(_ context: ScriptExecutionContext) throws {
        // do nothing
    }
}

public struct OpNop10: OpCodeProtocol {
    public var value: UInt8 { return 0xb9 }
    public var name: String { return "OP_NOP10" }

    public func mainProcess(_ context: ScriptExecutionContext) throws {
        // do nothing
    }
}
