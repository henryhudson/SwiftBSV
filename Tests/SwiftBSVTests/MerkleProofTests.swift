//
//  MerkleProofTests.swift
//  SwiftBSV
//
//  TSC merkle proofs against real chain data. Block 956,001 holds 48
//  transactions, so its level of width 3 duplicates its last node, and
//  WhatsOnChain marks that duplicated sibling "*" in the proofs of
//  transactions 32 to 47. The fixtures are WhatsOnChain's own responses for
//  /block/<hash>/header and /tx/<txid>/proof/tsc, saved verbatim.
//

import Foundation
import XCTest
@testable import SwiftBSV

final class MerkleProofTests: XCTestCase {

    private let verifier = MerkleVerifier()

    func testBlock956001ProofWithDuplicatedRightSiblingVerifies() throws {
        // Index 47: at node 4 the working node is index 2 of a level of
        // width 3, a left-hand node with no right-hand partner, so "*".
        let proof = try fixtureProof("block-956001-tx-47-proof-tsc.json")
        XCTAssertEqual(proof.nodes[4], "*")
        XCTAssertTrue(verifier.verifyTSCProof(proof, expectedMerkleRoot: try block956001MerkleRoot()))
    }

    func testBlock956001ProofWithoutDuplicatedSiblingVerifies() throws {
        let proof = try fixtureProof("block-956001-tx-0-proof-tsc.json")
        XCTAssertFalse(proof.nodes.contains("*"))
        XCTAssertTrue(verifier.verifyTSCProof(proof, expectedMerkleRoot: try block956001MerkleRoot()))
    }

    func testDuplicatedSiblingOnTheLeftIsRefused() throws {
        // Index 63 differs from 47 only at node 4, where it makes the working
        // node a right-hand node. hash(c | c) is the same either way round,
        // so reading "*" without the side check would prove transaction 47
        // at a position that a 48-transaction block does not have.
        let real = try fixtureProof("block-956001-tx-47-proof-tsc.json")
        let leftDuplicate = TSCMerkleProof(index: 63, txOrId: real.txOrId, target: real.target, nodes: real.nodes)
        XCTAssertFalse(verifier.verifyTSCProof(leftDuplicate, expectedMerkleRoot: try block956001MerkleRoot()))
    }

    func testDuplicatedSiblingProofIsRefusedAgainstAnotherRoot() throws {
        let proof = try fixtureProof("block-956001-tx-47-proof-tsc.json")
        let otherRoot = String(try block956001MerkleRoot().dropLast()) + "6"
        XCTAssertFalse(verifier.verifyTSCProof(proof, expectedMerkleRoot: otherRoot))
    }

    // MARK: - Fixtures

    private struct Header: Decodable {
        let merkleroot: String
    }

    private func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Resources/merkle-proofs/\(name)"))
    }

    private func fixtureProof(_ name: String) throws -> TSCMerkleProof {
        try XCTUnwrap(JSONDecoder().decode([TSCMerkleProof].self, from: fixture(name)).first)
    }

    private func block956001MerkleRoot() throws -> String {
        try JSONDecoder().decode(Header.self, from: fixture("block-956001-header.json")).merkleroot
    }
}
