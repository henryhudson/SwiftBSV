//
//  OP_VER.swift
//  BitcoinKit
//
//  Created by Shun Usami on 2018/08/08.
//  Copyright © 2018 BitcoinKit developers. All rights reserved.
//

import Foundation

// Chronicle upgrade: OP_VER pushes the transaction version onto the stack.
public struct OpVer: OpCodeProtocol {
    public var value: UInt8 { return 0x62 }
    public var name: String { return "OP_VER" }

    public func mainProcess(_ context: ScriptExecutionContext) throws {
        // Push transaction version (4-byte LE). Default to 1 if not set.
        let version: Int32 = Int32(context.transaction?.version ?? 1)
        try context.pushToStack(version)
    }
}
