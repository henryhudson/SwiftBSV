//
//  TestHelpers.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-20.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation

struct TestHelpers {

    /// The copied `Resources` folder (Package.swift: `.copy("Resources")`).
    /// Read through the test bundle, so it is found where the tests run — on an
    /// Android emulator the source tree is not there. Falls back to the source
    /// folder for any runner that has no bundle.
    static var resourcesURL: URL {
        if let bundled = Bundle.module.resourceURL?.appendingPathComponent("Resources"),
           FileManager.default.fileExists(atPath: bundled.path) {
            return bundled
        }
        return URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Resources")
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
