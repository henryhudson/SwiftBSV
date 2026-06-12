//
//  RestoredOpcodeTests.swift
//  SwiftBSV
//
//  Tests for BSV Genesis-restored opcodes (OP_MUL, OP_INVERT) and
//  overflow-safe arithmetic executors (OP_ADD, OP_SUB, OP_1ADD, OP_1SUB,
//  OP_NEGATE, OP_ABS).
//

import XCTest
@testable import SwiftBSV

final class RestoredOpcodeTests: XCTestCase {
    var context: ScriptExecutionContext!

    override func setUp() {
        super.setUp()
        context = ScriptExecutionContext()
    }

    // MARK: - OP_MUL (Genesis-restored)

    func testOpMulMultiplies() throws {
        try context.pushToStack(Int32(2))
        try context.pushToStack(Int32(3))
        try OpCode.OP_MUL.execute(context)
        XCTAssertEqual(try context.number(at: -1), 6)
        XCTAssertEqual(context.stack.count, 1)
    }

    func testOpMulNegative() throws {
        try context.pushToStack(Int32(-4))
        try context.pushToStack(Int32(5))
        try OpCode.OP_MUL.execute(context)
        XCTAssertEqual(try context.number(at: -1), -20)
    }

    func testOpMulByZero() throws {
        try context.pushToStack(Int32(Int32.max))
        try context.pushToStack(Int32(0))
        try OpCode.OP_MUL.execute(context)
        XCTAssertEqual(try context.number(at: -1), 0)
    }

    func testOpMulOverflowThrowsInvalidBignum() throws {
        try context.pushToStack(Int32.max)
        try context.pushToStack(Int32(2))
        XCTAssertThrowsError(try OpCode.OP_MUL.execute(context)) {
            guard case OpCodeExecutionError.invalidBignum = $0 else {
                return XCTFail("expected invalidBignum, got \($0)")
            }
        }
    }

    func testOpMulOverflowLeavesStackIntact() throws {
        try context.pushToStack(Int32.max)
        try context.pushToStack(Int32(2))
        _ = try? OpCode.OP_MUL.execute(context)
        XCTAssertEqual(context.stack.count, 2)
    }

    func testOpMulMinTimesNegOneThrowsInvalidBignum() throws {
        // Int32.min * -1 = 2_147_483_648 — fits Int64 but exceeds Int32.max.
        try context.pushToStack(Int32.min)
        try context.pushToStack(Int32(-1))
        XCTAssertThrowsError(try OpCode.OP_MUL.execute(context)) {
            guard case OpCodeExecutionError.invalidBignum = $0 else {
                return XCTFail("expected invalidBignum, got \($0)")
            }
        }
    }

    // MARK: - OP_INVERT (Genesis-restored)

    func testOpInvertFlipsBytes() throws {
        try context.pushToStack(Data([0x05, 0xff]))
        try OpCode.OP_INVERT.execute(context)
        XCTAssertEqual(context.data(at: -1), Data([0xfa, 0x00]))
        XCTAssertEqual(context.stack.count, 1)
    }

    func testOpInvertSingleByte() throws {
        try context.pushToStack(Data([0b10101010]))
        try OpCode.OP_INVERT.execute(context)
        XCTAssertEqual(context.data(at: -1), Data([0b01010101]))
    }

    func testOpInvertEmptyData() throws {
        try context.pushToStack(Data())
        try OpCode.OP_INVERT.execute(context)
        XCTAssertEqual(context.data(at: -1), Data())
        XCTAssertEqual(context.stack.count, 1)
    }

    // MARK: - OP_ADD overflow safety

    func testOpAddNormal() throws {
        try context.pushToStack(Int32(10))
        try context.pushToStack(Int32(32))
        try OpCode.OP_ADD.execute(context)
        XCTAssertEqual(try context.number(at: -1), 42)
    }

    func testOpAddOverflowThrowsInsteadOfTrapping() throws {
        try context.pushToStack(Int32.max)
        try context.pushToStack(Int32(1))
        XCTAssertThrowsError(try OpCode.OP_ADD.execute(context)) {
            guard case OpCodeExecutionError.invalidBignum = $0 else {
                return XCTFail("expected invalidBignum, got \($0)")
            }
        }
    }

    func testOpAddOverflowLeavesStackIntact() throws {
        try context.pushToStack(Int32.max)
        try context.pushToStack(Int32(1))
        _ = try? OpCode.OP_ADD.execute(context)
        XCTAssertEqual(context.stack.count, 2)
    }

    // MARK: - OP_SUB overflow safety

    func testOpSubNormal() throws {
        // OP_SUB: (x1 x2 -- x1-x2)
        try context.pushToStack(Int32(10))
        try context.pushToStack(Int32(3))
        try OpCode.OP_SUB.execute(context)
        XCTAssertEqual(try context.number(at: -1), 7)
    }

    func testOpSubOverflowThrowsInsteadOfTrapping() throws {
        // Int32.min - 1 underflows: x1=Int32.min, x2=1
        try context.pushToStack(Int32.min)
        try context.pushToStack(Int32(1))
        XCTAssertThrowsError(try OpCode.OP_SUB.execute(context)) {
            guard case OpCodeExecutionError.invalidBignum = $0 else {
                return XCTFail("expected invalidBignum, got \($0)")
            }
        }
    }

    func testOpSubOverflowLeavesStackIntact() throws {
        try context.pushToStack(Int32.min)
        try context.pushToStack(Int32(1))
        _ = try? OpCode.OP_SUB.execute(context)
        XCTAssertEqual(context.stack.count, 2)
    }

    // MARK: - OP_1ADD overflow safety

    func testOp1AddNormal() throws {
        try context.pushToStack(Int32(41))
        try OpCode.OP_1ADD.execute(context)
        XCTAssertEqual(try context.number(at: -1), 42)
    }

    func testOp1AddOverflowThrowsInsteadOfTrapping() throws {
        try context.pushToStack(Int32.max)
        XCTAssertThrowsError(try OpCode.OP_1ADD.execute(context)) {
            guard case OpCodeExecutionError.invalidBignum = $0 else {
                return XCTFail("expected invalidBignum, got \($0)")
            }
        }
    }

    func testOp1AddOverflowLeavesStackIntact() throws {
        try context.pushToStack(Int32.max)
        _ = try? OpCode.OP_1ADD.execute(context)
        XCTAssertEqual(context.stack.count, 1)
    }

    // MARK: - OP_1SUB overflow safety

    func testOp1SubNormal() throws {
        try context.pushToStack(Int32(43))
        try OpCode.OP_1SUB.execute(context)
        XCTAssertEqual(try context.number(at: -1), 42)
    }

    func testOp1SubOverflowThrowsInsteadOfTrapping() throws {
        try context.pushToStack(Int32.min)
        XCTAssertThrowsError(try OpCode.OP_1SUB.execute(context)) {
            guard case OpCodeExecutionError.invalidBignum = $0 else {
                return XCTFail("expected invalidBignum, got \($0)")
            }
        }
    }

    func testOp1SubOverflowLeavesStackIntact() throws {
        try context.pushToStack(Int32.min)
        _ = try? OpCode.OP_1SUB.execute(context)
        XCTAssertEqual(context.stack.count, 1)
    }

    // MARK: - OP_NEGATE overflow safety

    func testOpNegateNormal() throws {
        try context.pushToStack(Int32(42))
        try OpCode.OP_NEGATE.execute(context)
        XCTAssertEqual(try context.number(at: -1), -42)
    }

    func testOpNegateIntMinThrowsInsteadOfTrapping() throws {
        // -Int32.min overflows: there is no positive counterpart in Int32.
        try context.pushToStack(Int32.min)
        XCTAssertThrowsError(try OpCode.OP_NEGATE.execute(context)) {
            guard case OpCodeExecutionError.invalidBignum = $0 else {
                return XCTFail("expected invalidBignum, got \($0)")
            }
        }
    }

    func testOpNegateIntMinLeavesStackIntact() throws {
        try context.pushToStack(Int32.min)
        _ = try? OpCode.OP_NEGATE.execute(context)
        XCTAssertEqual(context.stack.count, 1)
    }

    // MARK: - OP_ABS overflow safety

    func testOpAbsNormal() throws {
        try context.pushToStack(Int32(-42))
        try OpCode.OP_ABS.execute(context)
        XCTAssertEqual(try context.number(at: -1), 42)
    }

    func testOpAbsIntMinThrowsInsteadOfTrapping() throws {
        // abs(Int32.min) overflows: there is no positive counterpart in Int32.
        try context.pushToStack(Int32.min)
        XCTAssertThrowsError(try OpCode.OP_ABS.execute(context)) {
            guard case OpCodeExecutionError.invalidBignum = $0 else {
                return XCTFail("expected invalidBignum, got \($0)")
            }
        }
    }

    func testOpAbsIntMinLeavesStackIntact() throws {
        try context.pushToStack(Int32.min)
        _ = try? OpCode.OP_ABS.execute(context)
        XCTAssertEqual(context.stack.count, 1)
    }
}
