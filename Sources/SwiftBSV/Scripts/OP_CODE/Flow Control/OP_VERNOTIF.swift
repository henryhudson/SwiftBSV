//
//  OP_VERNOTIF.swift
//  BitcoinKit
//
//  Created by Shun Usami on 2018/08/08.
//  Copyright © 2018 BitcoinKit developers. All rights reserved.
//

import Foundation

// Chronicle upgrade: OP_VERNOTIF — negated version-conditional IF.
public struct OpVerNotIf: OpCodeProtocol {
    public var value: UInt8 { return 0x66 }
    public var name: String { return "OP_VERNOTIF" }

    public func mainProcess(_ context: ScriptExecutionContext) throws {
        try context.assertStackHeightGreaterThanOrEqual(1)
        let threshold = try context.number(at: -1)
        context.stack.removeLast()
        let version: Int32 = Int32(context.transaction?.version ?? 1)
        try context.pushToStack(version < threshold ? 1 : 0)
    }
}
