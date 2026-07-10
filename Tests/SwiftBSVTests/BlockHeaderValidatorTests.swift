//
//  BlockHeaderValidatorTests.swift
//  SwiftBSV
//
//  Proof-of-work limit correctness and the checkpoint-anchored difficulty floor.
//

import Foundation
import XCTest
@testable import SwiftBSV

final class BlockHeaderValidatorTests: XCTestCase {

    // Genesis compact bits and a couple of real mainnet-scale bits values.
    private let genesisBits = "1d00ffff"       // the consensus pow limit
    private let easierThanGenesisBits = "1e00ffff" // one byte more significant → easier than genesis
    private let checkpointBits = "1822ed6f"    // Henceforth mainnet checkpoint @ 944000

    func testMainnetPowLimitEqualsGenesisTarget() {
        // The default validator decodes the genesis bits to exactly the pow
        // limit — the off-by-one that made the limit 256× too lenient would
        // break this equality.
        let target = BlockHeaderValidator().targetFromBits(bits: genesisBits)
        XCTAssertEqual(target, BlockHeaderValidator.mainnetPowLimit,
                       "Genesis bits must decode to exactly mainnetPowLimit")
    }

    func testDefaultValidatorRejectsEasierThanGenesis() {
        // A target easier than genesis is above the consensus limit and must be
        // rejected — before the pow-limit fix this was accepted.
        XCTAssertNil(BlockHeaderValidator().targetFromBits(bits: easierThanGenesisBits),
                     "A target easier than genesis must be rejected by the default limit")
    }

    func testDefaultValidatorAcceptsGenesisAndCheckpointDifficulty() {
        let v = BlockHeaderValidator()
        XCTAssertNotNil(v.targetFromBits(bits: genesisBits))
        XCTAssertNotNil(v.targetFromBits(bits: checkpointBits))
    }

    func testCheckpointAnchoredFloorRejectsGenesisForgery() {
        // A floor set well below the checkpoint difficulty (here a synthetic
        // mid-range target, easier than the checkpoint but far harder than
        // genesis) must reject a genesis-difficulty header while still
        // accepting a header at the checkpoint's real difficulty. This is what
        // makes a cheaply-mined genesis-difficulty forgery fail to validate
        // against a chain whose real difficulty is orders of magnitude higher.
        let floor = BlockHeaderValidator().targetFromBits(bits: "1a00ffff")! // easier than checkpoint, far harder than genesis
        let floored = BlockHeaderValidator(maxTarget: floor)

        XCTAssertNil(floored.targetFromBits(bits: genesisBits),
                     "A genesis-difficulty header must be rejected by a checkpoint-anchored floor")
        XCTAssertNotNil(floored.targetFromBits(bits: checkpointBits),
                        "A header at the checkpoint's real difficulty must still be accepted")
    }

    func testFlooredValidatorIsBackwardCompatibleByDefault() {
        // No floor argument ⇒ the consensus limit ⇒ identical to the historical
        // behaviour (every existing caller constructs BlockHeaderValidator()).
        XCTAssertEqual(BlockHeaderValidator().maxTarget, BlockHeaderValidator.mainnetPowLimit)
    }
}
