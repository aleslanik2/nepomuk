// nepomuk-touchid – seals a password with a Secure Enclave key that can be used only after
// Touch ID on this Mac with the currently enrolled fingers (biometryCurrentSet).
//
//   nepomuk-touchid available            exit 0 when Touch ID and the Secure Enclave are usable
//   nepomuk-touchid seal  < secret       prints a JSON blob (no prompt: uses the public key)
//   nepomuk-touchid open "reason" < blob prints the secret after Touch ID
//
// The Secure Enclave key never leaves the chip; its `dataRepresentation` is an opaque handle
// that only this device's Secure Enclave can use. Re-enrolling fingers invalidates it.

import CryptoKit
import Foundation
import LocalAuthentication

let info = Data("nepomuk/touchid/v1".utf8)

struct Blob: Codable {
    var version: Int
    var key: String   // Secure Enclave key handle (dataRepresentation), base64
    var eph: String   // ephemeral public key (x963), base64
    var box: String   // ChaChaPoly combined (nonce | ciphertext | tag), base64
}

func fail(_ message: String, _ code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data("nepomuk-touchid: \(message)\n".utf8))
    exit(code)
}

func readStdin() -> Data {
    FileHandle.standardInput.readDataToEndOfFile()
}

func deriveKey(_ shared: SharedSecret, eph: Data) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: eph, sharedInfo: info, outputByteCount: 32)
}

func biometryAvailable() -> Bool {
    var error: NSError?
    let ok = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    return ok && SecureEnclave.isAvailable
}

let args = CommandLine.arguments
guard args.count >= 2 else { fail("usage: nepomuk-touchid available | seal | open <reason>", 2) }

switch args[1] {
case "available":
    exit(biometryAvailable() ? 0 : 1)

case "seal":
    guard biometryAvailable() else { fail("Touch ID is not available", 3) }
    var secret = readStdin()
    defer { secret.resetBytes(in: 0..<secret.count) }
    var acError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &acError)
    else { fail("cannot create the access control") }
    do {
        let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let eph = P256.KeyAgreement.PrivateKey()
        let ephPub = eph.publicKey.x963Representation
        let shared = try eph.sharedSecretFromKeyAgreement(with: seKey.publicKey)
        let box = try ChaChaPoly.seal(secret, using: deriveKey(shared, eph: ephPub))
        let blob = Blob(version: 1, key: seKey.dataRepresentation.base64EncodedString(),
                        eph: ephPub.base64EncodedString(), box: box.combined.base64EncodedString())
        FileHandle.standardOutput.write(try JSONEncoder().encode(blob))
    } catch {
        fail("sealing failed: \(error.localizedDescription)")
    }

case "open":
    let reason = args.count >= 3 ? args[2] : "unlock nepomuk"
    do {
        let blob = try JSONDecoder().decode(Blob.self, from: readStdin())
        guard let keyData = Data(base64Encoded: blob.key), let ephData = Data(base64Encoded: blob.eph),
              let boxData = Data(base64Encoded: blob.box)
        else { fail("malformed blob") }
        let context = LAContext()
        context.localizedReason = reason
        context.localizedCancelTitle = "Use password"
        let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData, authenticationContext: context)
        let ephPub = try P256.KeyAgreement.PublicKey(x963Representation: ephData)
        // This is where Touch ID is required.
        let shared = try seKey.sharedSecretFromKeyAgreement(with: ephPub)
        var secret = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: boxData), using: deriveKey(shared, eph: ephData))
        FileHandle.standardOutput.write(secret)
        secret.resetBytes(in: 0..<secret.count)
    } catch {
        fail("Touch ID did not unlock the password: \(error.localizedDescription)", 4)
    }

default:
    fail("unknown command \(args[1])", 2)
}
