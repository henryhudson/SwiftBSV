//
//  OP_VERIF.swift
//  BitcoinKit
//
//  Created by Shun Usami on 2018/08/08.
//  Copyright © 2018 BitcoinKit developers. All rights reserved.
//

import Foundation

// Chronicle upgrade: OP_VERIF — version-conditional IF.
// Equivalent to OP_VER OP_GREATERTHANOREQUAL OP_IF.
public struct OpVerIf: OpCodeProtocol {
    public var value: UInt8 { return 0x65 }
    public var name: String { return "OP_VERIF" }

    public func mainProcess(_ context: ScriptExecutionContext) throws {
        try context.assertStackHeightGreaterThanOrEqual(1)
        let threshold = try context.number(at: -1)
        context.stack.removeLast()
        let version: Int32 = Int32(context.transaction?.version ?? 1)
        try context.pushToStack(version >= threshold ? 1 : 0)
    }
}
