import Capacitor
import Foundation
import LocalAuthentication
import Security

/// The decision-maker's signing key, kept by iOS behind Face ID / Touch ID.
/// docs/adr/0016.
///
/// The key is a Keychain item whose access control is `.biometryCurrentSet`:
///   * iOS hands it out only after a successful biometric check, for that one read;
///     the passcode is NOT a fallback -- whoever learnt the passcode by watching
///     cannot sign an order with it;
///   * adding or removing a fingerprint or a face makes the item unreadable for
///     good -- a new enrolment is the way back, by design;
///   * `WhenPasscodeSetThisDeviceOnly`: never in a backup, never on another phone,
///     gone if the passcode is removed.
///
/// Public facts about each key (person, organisation, key id) sit beside it in
/// UserDefaults: nothing in them signs, and the app lists keys without a prompt.
@objc(DeviceVaultPlugin)
public class DeviceVaultPlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "DeviceVaultPlugin"
    public let jsName = "DeviceVault"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "status", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "list", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "store", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "load", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "remove", returnType: CAPPluginReturnPromise),
    ]

    private let service = "alerting.device-vault"
    private let metaKey = "alerting.device-vault.meta"
    private let queue = DispatchQueue(label: "alerting.device-vault", qos: .userInitiated)

    // MARK: - status

    @objc func status(_ call: CAPPluginCall) {
        let context = LAContext()
        var error: NSError?
        let available = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        var result: [String: Any] = ["available": available, "biometry": biometryName(context.biometryType)]
        if !available {
            result["reason"] = reasonCode(error)
        }
        call.resolve(result)
    }

    // MARK: - list

    @objc func list(_ call: CAPPluginCall) {
        let metas = UserDefaults.standard.dictionary(forKey: metaKey) as? [String: String] ?? [:]
        let items = metas.sorted { $0.key < $1.key }.map { ["alias": $0.key, "meta": $0.value] }
        call.resolve(["items": items])
    }

    // MARK: - store

    @objc func store(_ call: CAPPluginCall) {
        guard let alias = call.getString("alias"), !alias.isEmpty,
              let secretText = call.getString("secret"), let secret = Self.fromB64u(secretText) else {
            call.reject("alias и secret обязательны", "failed")
            return
        }
        let meta = call.getString("meta") ?? "{}"
        let context = LAContext()
        var probe: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &probe) else {
            call.reject("биометрия недоступна", reasonCode(probe))
            return
        }
        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &acError
        ) else {
            call.reject("не удалось задать защиту ключа", "unavailable")
            return
        }
        queue.async {
            self.deleteItem(alias)
            let attributes: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: self.service,
                kSecAttrAccount as String: alias,
                kSecValueData as String: secret,
                kSecAttrAccessControl as String: access,
            ]
            let status = SecItemAdd(attributes as CFDictionary, nil)
            guard status == errSecSuccess else {
                call.reject("ключ не сохранён (\(status))", self.code(for: status, alias: alias))
                return
            }
            var metas = UserDefaults.standard.dictionary(forKey: self.metaKey) as? [String: String] ?? [:]
            metas[alias] = meta
            UserDefaults.standard.set(metas, forKey: self.metaKey)
            call.resolve()
        }
    }

    // MARK: - load

    @objc func load(_ call: CAPPluginCall) {
        guard let alias = call.getString("alias"), !alias.isEmpty else {
            call.reject("alias обязателен", "failed")
            return
        }
        let context = LAContext()
        // What the system prompt says: the app names the operation (sign which
        // order, log in, renew), so the person knows what the face is for.
        context.localizedReason = call.getString("reason") ?? "Подтвердите, что это вы"
        // No "Enter Password" button: the passcode is not a way to the key.
        context.localizedFallbackTitle = ""
        queue.async {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: self.service,
                kSecAttrAccount as String: alias,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecUseAuthenticationContext as String: context,
            ]
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            guard status == errSecSuccess, let data = item as? Data else {
                call.reject("ключ не выдан (\(status))", self.code(for: status, alias: alias))
                return
            }
            call.resolve(["secret": Self.b64u(data)])
        }
    }

    // MARK: - remove

    @objc func remove(_ call: CAPPluginCall) {
        guard let alias = call.getString("alias"), !alias.isEmpty else {
            call.reject("alias обязателен", "failed")
            return
        }
        queue.async {
            self.deleteItem(alias)
            var metas = UserDefaults.standard.dictionary(forKey: self.metaKey) as? [String: String] ?? [:]
            metas.removeValue(forKey: alias)
            UserDefaults.standard.set(metas, forKey: self.metaKey)
            call.resolve()
        }
    }

    // MARK: - helpers

    private func deleteItem(_ alias: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: alias,
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// The codes app.js turns into words (logic.js: VAULT_ERRORS).
    private func code(for status: OSStatus, alias: String) -> String {
        switch status {
        case errSecUserCanceled:
            return "cancelled"
        case errSecAuthFailed:
            return "failed"
        case errSecItemNotFound:
            // The facts are here but the item is not: a changed set of fingerprints
            // or faces made it unreadable (.biometryCurrentSet), or the passcode was
            // removed. Either way: a new key and a new enrolment.
            let metas = UserDefaults.standard.dictionary(forKey: metaKey) as? [String: String] ?? [:]
            return metas[alias] != nil ? "invalidated" : "not_found"
        case errSecInteractionNotAllowed:
            return "unavailable"
        default:
            return "failed"
        }
    }

    private func reasonCode(_ error: NSError?) -> String {
        guard let error, let code = LAError.Code(rawValue: error.code) else { return "unavailable" }
        switch code {
        case .biometryNotEnrolled, .passcodeNotSet:
            return "not_enrolled"
        case .biometryLockout:
            return "locked"
        default:
            return "unavailable"
        }
    }

    private func biometryName(_ type: LABiometryType) -> String {
        switch type {
        case .faceID: return "face"
        case .touchID: return "fingerprint"
        default:
            if #available(iOS 17.0, *), type == .opticID { return "iris" }
            return "none"
        }
    }

    /// base64url without padding, as devicekey.js writes it.
    static func b64u(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func fromB64u(_ text: String) -> Data? {
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return Data(base64Encoded: base64)
    }
}
