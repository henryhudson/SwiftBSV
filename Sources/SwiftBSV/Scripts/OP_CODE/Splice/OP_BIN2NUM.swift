//
//  OP_BIN2NUM.swift
//
//  BSV consensus: re-encode a byte sequence as a minimal script number.
//
//  Stack: ( bin -- num )
//
//  Decodes `bin` as a script-num buffer (little-endian, MSB sign bit) and
//  re-emits it in the canonical minimal form: trailing zero bytes are
//  stripped, the sign bit migrates to the new MSB. Empty input maps to
//  empty output (= zero). Fails if the result exceeds `BInt.scriptNumMaxBytes`.
//

import Foundation

public struct OpBin2Num: OpCodeProtocol {
    public var value: UInt8 { return 0x81 }
    public var name: String { return "OP_BIN2NUM" }

    public func mainProcess(_ context: ScriptExecutionContext) throws {
        try context.assertStackHeightGreaterThanOrEqual(1)

        let bin = context.stack.removeLast()
        let minimal = BInt(fromScriptNumBuffer: bin).toScriptNumBuffer()

        // BSV pre-Genesis caps script-arithmetic numbers at 4 bytes. Most
        // BSV nodes today still enforce this for OP_BIN2NUM specifically —
        // the post-Genesis script size loosening did NOT lift the
        // arithmetic operand width. Keep aligned with what
        // `ScriptExecutionContext.number(at:)` enforces (≤ 4 bytes).
        guard minimal.count <= 4 else {
            throw OpCodeExecutionError.error("OP_BIN2NUM: result exceeds 4-byte script-num limit")
        }

        try context.pushToStack(minimal)
    }
}
