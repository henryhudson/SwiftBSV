# SwiftBSV

A pure-Swift SDK for Bitcoin SV — keys, addresses, HD wallets, transactions, scripts, signatures, encryption, and SPV verification.

This fork at `henryhudson/SwiftBSV` continues from Will Townsend's [original SwiftBSV](https://github.com/wtsnz/SwiftBSV), updated for Swift 6 strict concurrency, modern Apple platforms (iOS 16+, macOS 13+, tvOS 16+), and BSV protocol decisions including the Chronicle-restored opcode set, FORKID sighash by default, and BRC-2 ECIES (BIE1 wire format).

## Capabilities

| Module | Status | Notes |
|---|---|---|
| **BInt** — arbitrary-precision integers | ✓ | `Sendable`, all comparison and arithmetic ops |
| **Base58 / Base58Check** | ✓ | Round-trips through every spec-conformant tool |
| **Point** — secp256k1 curve points | ✓ | x / y as `BInt`, used internally by `PublicKey` |
| **PrivateKey** | ✓ | Random / from data / from BInt / from buffer / from WIF |
| **PublicKey** | ✓ | Hex / DER (strict and lax), compressed and uncompressed |
| **Address** | ✓ | P2PKH for mainnet and testnet, output script generation |
| **Bip39** — mnemonic seeds | ✓ | 12 / 24 word, optional passphrase |
| **Bip32** — HD wallet derivation | ✓ | Full BIP-32: hardened / non-hardened / public-only / xprv ↔ xpub |
| **Type42** — BRC-42 invoice keys | ✓ | derivePrivate / derivePublic / deriveSelf / ECDH shared secret |
| **Signature** — ECDSA | ✓ | DER + transaction format with FORKID sighash byte |
| **BitcoinSignedMessage** | ✓ | BSM compact-signature sign and verify, crash-safe |
| **ECIESEncryption** — BIE1 wire format | ✓ | Wire-compatible with `@bsv/sdk` `EncryptedMessage` |
| **Script + OpCode** | ✓ | Full BSV opcode set including Chronicle restorations |
| **TxBuilder** — fluent transaction construction | ✓ | Inputs, outputs, fee per kB, change, sign per input |
| **SPV — block headers + Merkle proofs** | ✓ | PoW + chain link validation; standard / TSC / WoC proof formats |

## Installation

### Swift Package Manager

In Xcode: **File → Add Packages…** → paste `https://github.com/henryhudson/SwiftBSV` → select branch `main`.

In `Package.swift`:

```swift
// swift-tools-version:5.9
dependencies: [
    .package(url: "https://github.com/henryhudson/SwiftBSV", branch: "main")
]
```

Minimum platform requirements: **iOS 16 / macOS 13 / tvOS 16**.

## Documentation

The full documentation is a 41-page LaTeX book in [`Documentation/swiftbsv.pdf`](Documentation/swiftbsv.pdf) — read it on GitHub directly (PDFs render in-browser) or clone and view locally. The `.tex` source is alongside it for contributors.

The book covers every public type with worked examples: cryptographic primitives, keys and addresses, HD wallets, Type42 (BRC-42) invoice-numbered derivation, signatures, ECIES, scripts and opcodes, transactions, SPV verification, and SwiftPM integration.

## Quick Examples

### Generate a mnemonic and derive a key

```swift
let mnemonic = Bip39.create()
let seed = Bip39.createSeed(mnemonic: mnemonic)
let root = Bip32(seed: seed, network: .mainnet)
let receive = root.derivedKey(path: "m/44'/236'/0'/0/0")!

print(receive.address)  // 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

### Sign and verify a Bitcoin Signed Message

```swift
let key = PrivateKey(network: .mainnet)
let sig = BitcoinSignedMessage.sign(message: "hello!", privateKey: key)
let ok = BitcoinSignedMessage.verify(message: "hello!", signature: sig, address: key.address)
print(ok)  // true
```

### Build, sign, and serialize a transaction

```swift
let alice = PrivateKey(network: .mainnet)
let bob = Address(fromString: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", network: .mainnet)!

let utxo = TransactionOutput(
    value: 100_000,
    lockingScript: alice.address.toTxOutputScript().data
)

let builder = TxBuilder()
    .setFeePerKb(50)
    .setChangeAddress(alice.address)
    .inputFromPubKeyHash(
        txHashBuffer: prevTxid,
        txOutNum: 0,
        txOut: utxo,
        pubKey: alice.publicKey
    )
    .outputToAddress(value: 50_000, address: bob)

let built = try builder.build(useAllInputs: true)
_ = built.signInTx(nIn: 0, privateKey: alice)

let raw: Data = built.transaction.serialized()
let txid: String = built.transaction.txID
```

### Encrypt a message (BRC-2 ECIES, BIE1 wire format)

```swift
let recipient = PrivateKey(network: .mainnet)

let cipher = try ECIESEncryption.encrypt(
    plaintext: "secret".data(using: .utf8)!,
    recipientPublicKey: recipient.publicKey,
    senderPrivateKey: nil
)

let recovered = try ECIESEncryption.decrypt(
    ciphertext: cipher,
    privateKey: recipient
)
```

More worked examples in [`Documentation/swiftbsv.pdf`](Documentation/swiftbsv.pdf).

## Concurrency

Every public type that crosses an actor boundary in real consumer code is `Sendable` — no `@preconcurrency import` required. Pass `PrivateKey`, `PublicKey`, `Address`, `Bip32`, `Signature`, `MerkleProof`, `Transaction` and `ChainValidationResult` freely between `@MainActor` and detached `Task` contexts.

`TxBuilder` is non-`Sendable` by design (its purpose is incremental mutation); build the transaction on one isolation domain and pass the resulting `Transaction` value across boundaries.

## Author

**Will Townsend** wrote the original SwiftBSV at [wtsnz/SwiftBSV](https://github.com/wtsnz/SwiftBSV) — BIP-32, BIP-39, BInt, Base58Check, the original `TxBuilder`, and the structural skeleton this fork still rests on.

**Henry Hudson** maintains this fork — [github.com/henryhudson/SwiftBSV](https://github.com/henryhudson/SwiftBSV). Additions since the fork: Type42 (BRC-42), BRC-2 ECIES (BIE1), full SPV verification (block headers + Merkle proofs in three formats), defensive `Data` slicing across the public surface, Swift 6 strict-concurrency conformances, GitHub Actions CI on macOS 15 + Xcode 16, and the documentation book in `Documentation/`.

## License

SwiftBSV is available under the MIT license. See [LICENCE.md](LICENCE.md) for the full text.

## Acknowledgements

This project would not exist without the open-source work of:

- [wtsnz/SwiftBSV](https://github.com/wtsnz/SwiftBSV) — Will Townsend's original SwiftBSV
- [moneybutton/bsv](https://github.com/moneybutton/bsv) — the JavaScript BSV library whose API shape SwiftBSV mirrors
- [yenom/BitcoinKit](https://github.com/yenom/BitcoinKit) — Yenom team's BitcoinKit for Swift
- [KevinVitale/WalletKit](https://github.com/KevinVitale/WalletKit) — Kevin Vitale's WalletKit
- [yuzushioh/HDWalletKit](https://github.com/yuzushioh/HDWalletKit) — yuzushioh's HDWalletKit
- [Boilertalk/secp256k1.swift](https://github.com/Boilertalk/secp256k1.swift) — Swift binding to Pieter Wuille's `libsecp256k1`
- [krzyzanowskim/CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift) — Marcin Krzyżanowski's CryptoSwift, used for RIPEMD-160 and AES-CBC
