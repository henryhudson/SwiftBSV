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

    func testDuplicatedSiblingWrittenAsHexVerifies() throws {
        let real = try fixtureProof("block-956001-tx-47-proof-tsc.json")
        let spelledOut = TSCMerkleProof(index: 47, txOrId: real.txOrId, target: real.target, nodes: replacingStar(in: real.nodes, with: workingHashAtNode4))
        XCTAssertTrue(verifier.verifyTSCProof(spelledOut, expectedMerkleRoot: try block956001MerkleRoot()))
    }

    func testDuplicatedSiblingWrittenAsHexOnTheLeftIsRefused() throws {
        // The false position at index 63 again, with the copy written as hex
        // instead of "*". The standard's rule is about equal nodes, not the
        // marker, and Data(hex:) reads every spelling here as the same bytes.
        let real = try fixtureProof("block-956001-tx-47-proof-tsc.json")
        let root = try block956001MerkleRoot()
        for hex in [workingHashAtNode4, workingHashAtNode4.uppercased(), "0x" + workingHashAtNode4] {
            let leftDuplicate = TSCMerkleProof(index: 63, txOrId: real.txOrId, target: real.target, nodes: replacingStar(in: real.nodes, with: hex))
            XCTAssertFalse(verifier.verifyTSCProof(leftDuplicate, expectedMerkleRoot: root), hex)
        }
    }

    func testDuplicatedSiblingProofIsRefusedAgainstAnotherRoot() throws {
        let proof = try fixtureProof("block-956001-tx-47-proof-tsc.json")
        let otherRoot = String(try block956001MerkleRoot().dropLast()) + "6"
        XCTAssertFalse(verifier.verifyTSCProof(proof, expectedMerkleRoot: otherRoot))
    }

    // MARK: - Fixtures

    /// The calculated node at node 4 of transaction 47's proof: the hash
    /// that its "*" stands for.
    private let workingHashAtNode4 = "6fb9411770e02550e4f99f2f5db63f6eeb4fa76ffdaa9cc09a65aec06beae368"

    private func replacingStar(in nodes: [String], with hex: String) -> [String] {
        nodes.map { $0 == "*" ? hex : $0 }
    }

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
