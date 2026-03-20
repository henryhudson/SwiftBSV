//
//  MerkleProof.swift
//  SwiftBSV
//
//  SPV Merkle proof models and verification.
//  Supports standard, TSC (BRC-74), and WhatsOnChain proof formats.
//

import Foundation
import CryptoSwift

// MARK: - Merkle Proof Models

/// Represents a Merkle proof for SPV verification
public struct MerkleProof: Codable {
    public let txid: String
    public let blockHash: String
    public let blockHeight: Int?
    public let merkleRoot: String
    public let index: Int
    public let nodes: [String]

    public init(txid: String, blockHash: String, blockHeight: Int? = nil, merkleRoot: String, index: Int, nodes: [String]) {
        self.txid = txid
        self.blockHash = blockHash
        self.blockHeight = blockHeight
        self.merkleRoot = merkleRoot
        self.index = index
        self.nodes = nodes
    }
}

/// TSC (Technical Standards Committee) Merkle proof format
public struct TSCMerkleProof: Codable {
    public let index: Int
    public let txOrId: String
    public let target: String?
    public let nodes: [String]
    public let targetType: String?
    public let proofType: String?
    public let composite: Bool?

    public init(index: Int, txOrId: String, target: String?, nodes: [String], targetType: String? = nil, proofType: String? = nil, composite: Bool? = nil) {
        self.index = index
        self.txOrId = txOrId
        self.target = target
        self.nodes = nodes
        self.targetType = targetType
        self.proofType = proofType
        self.composite = composite
    }
}

/// WhatsOnChain API Merkle proof response
public struct WOCMerkleProof: Codable {
    public let blockHash: String
    public let branches: [WOCMerkleBranch]
    public let hash: String
    public let merkleRoot: String

    public struct WOCMerkleBranch: Codable {
        public let hash: String
        public let pos: String  // "L" for left, "R" for right

        public init(hash: String, pos: String) {
            self.hash = hash
            self.pos = pos
        }
    }

    public init(blockHash: String, branches: [WOCMerkleBranch], hash: String, merkleRoot: String) {
        self.blockHash = blockHash
        self.branches = branches
        self.hash = hash
        self.merkleRoot = merkleRoot
    }
}

// MARK: - SPV Result Types

/// Result of SPV verification
public struct SPVVerificationResult {
    public let isValid: Bool
    public let txid: String
    public let blockHash: String
    public let blockHeight: Int?
    public let verifiedAt: Date
    public let error: SPVError?

    public init(isValid: Bool, txid: String, blockHash: String, blockHeight: Int? = nil, error: SPVError? = nil) {
        self.isValid = isValid
        self.txid = txid
        self.blockHash = blockHash
        self.blockHeight = blockHeight
        self.verifiedAt = Date()
        self.error = error
    }
}

/// Tracks SPV verification status for a transaction
public struct SPVTransactionStatus: Codable {
    public let txid: String
    public var isVerified: Bool
    public var verificationDate: Date?
    public var blockHash: String?
    public var blockHeight: Int?
    public var merkleProof: MerkleProof?

    public init(txid: String, isVerified: Bool = false) {
        self.txid = txid
        self.isVerified = isVerified
    }

    public mutating func markVerified(proof: MerkleProof) {
        self.isVerified = true
        self.verificationDate = Date()
        self.blockHash = proof.blockHash
        self.blockHeight = proof.blockHeight
        self.merkleProof = proof
    }
}

/// SPV error types
public enum SPVError: Error, LocalizedError {
    case invalidMerkleProof
    case blockHeaderNotFound
    case merkleRootMismatch
    case invalidProofFormat
    case networkError(String)
    case txNotInBlock
    case invalidBlockHash

    public var errorDescription: String? {
        switch self {
        case .invalidMerkleProof: return "Invalid Merkle proof structure"
        case .blockHeaderNotFound: return "Block header not found"
        case .merkleRootMismatch: return "Merkle root mismatch"
        case .invalidProofFormat: return "Invalid proof format"
        case .networkError(let message): return "Network error: \(message)"
        case .txNotInBlock: return "Merkle proof not available for this transaction"
        case .invalidBlockHash: return "Invalid block hash"
        }
    }
}

// MARK: - Merkle Verifier

/// Verifies Merkle proofs for SPV (Simplified Payment Verification).
/// Supports standard, TSC, and WhatsOnChain proof formats.
public struct MerkleVerifier {

    public init() {}

    /// Verify a standard Merkle proof against a known Merkle root.
    public func verifyMerkleProof(_ proof: MerkleProof, expectedMerkleRoot: String) -> Bool {
        var currentHash = proof.txid
        var index = proof.index

        for node in proof.nodes {
            let isLeft = (index % 2 == 0)
            if isLeft {
                currentHash = doubleSHA256HashPair(left: currentHash, right: node)
            } else {
                currentHash = doubleSHA256HashPair(left: node, right: currentHash)
            }
            index = index / 2
        }

        return currentHash.lowercased() == expectedMerkleRoot.lowercased()
    }

    /// Verify a TSC format Merkle proof.
    public func verifyTSCProof(_ tscProof: TSCMerkleProof, expectedMerkleRoot: String) -> Bool {
        let proof = MerkleProof(
            txid: tscProof.txOrId,
            blockHash: tscProof.target ?? "",
            merkleRoot: expectedMerkleRoot,
            index: tscProof.index,
            nodes: tscProof.nodes
        )
        return verifyMerkleProof(proof, expectedMerkleRoot: expectedMerkleRoot)
    }

    /// Verify a WhatsOnChain Merkle proof against an independently-fetched block header root.
    public func verifyWOCProofAgainstRoot(_ wocProof: WOCMerkleProof, expectedMerkleRoot: String) -> Bool {
        let computedRoot = computeWOCMerkleRoot(wocProof)
        return computedRoot.lowercased() == expectedMerkleRoot.lowercased()
    }

    /// Verify a WhatsOnChain Merkle proof against its own embedded root.
    public func verifyWOCProof(_ wocProof: WOCMerkleProof) -> Bool {
        return verifyWOCProofAgainstRoot(wocProof, expectedMerkleRoot: wocProof.merkleRoot)
    }

    /// Compute the Merkle root from a WOC proof by traversing branches.
    public func computeWOCMerkleRoot(_ wocProof: WOCMerkleProof) -> String {
        var currentHash = wocProof.hash

        for branch in wocProof.branches {
            if branch.pos == "L" {
                currentHash = doubleSHA256HashPair(left: branch.hash, right: currentHash)
            } else {
                currentHash = doubleSHA256HashPair(left: currentHash, right: branch.hash)
            }
        }

        return currentHash
    }

    // MARK: - Hashing

    /// Bitcoin double-SHA256 on a pair of display-order hex hashes.
    /// Input hashes are reversed to raw byte order, concatenated, double-hashed,
    /// then reversed back to display order.
    public func doubleSHA256HashPair(left: String, right: String) -> String {
        let leftBytes = Data(hex: left)
        let rightBytes = Data(hex: right)
        guard !leftBytes.isEmpty, !rightBytes.isEmpty else { return "" }

        var combined = Data(leftBytes.reversed())
        combined.append(Data(rightBytes.reversed()))

        let hash1 = Data(combined).sha256()
        let hash2 = Data(hash1).sha256()

        return Data(Data(hash2).reversed()).hex
    }
}
