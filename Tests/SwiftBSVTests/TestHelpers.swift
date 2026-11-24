//
//  TestHelpers.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-20.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation

struct TestHelpers {

    /// The vector `Resources` folder. On a Mac or in a Linux container it sits
    /// beside this source file. On an Android emulator only the test runner and
    /// its copied resource bundle (`*.resources`, per Package.swift's
    /// `.copy("Resources")`) are pushed, into the working directory, so look there
    /// next. (`Bundle.module` is not used: off Apple it points at the build
    /// machine's path and traps when that is absent.)
    static var resourcesURL: URL {
        let fileManager = FileManager.default
        let beside = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Resources")
        if fileManager.fileExists(atPath: beside.path) { return beside }

        let cwd = URL(fileURLWithPath: fileManager.currentDirectoryPath)
        let bundles = (try? fileManager.contentsOfDirectory(atPath: cwd.path)) ?? []
        for name in bundles where name.hasSuffix(".resources") {
            let copied = cwd.appendingPathComponent(name).appendingPathComponent("Resources")
            if fileManager.fileExists(atPath: copied.path) { return copied }
        }
        return beside
    }

    static func jsonResource(pathComponents: [String]) -> Any {

        let url = pathComponents.reduce(resourcesURL) { (result, component) in
            return result.appendingPathComponent(component)
        }

        let json = try! JSONSerialization.jsonObject(
            with: try! Data(contentsOf: url),
            options: []
        )

        return json
    }

}
