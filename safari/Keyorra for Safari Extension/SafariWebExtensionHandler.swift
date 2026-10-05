// Safari delivers browser.runtime.sendNativeMessage here (the application id is ignored).
// Each message is relayed to the Keyorra app as one frame and its one reply goes back, which
// is what the native host does for Chromium and Firefox.

import AppKit
import SafariServices
import os.log

final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    private static let log = OSLog(subsystem: "app.keyorra.safari.extension", category: "bridge")

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let message = item?.userInfo?[SFExtensionMessageKey]
        // Starting the app can take seconds; keep Safari's calling thread free.
        DispatchQueue.global(qos: .userInitiated).async {
            let reply: Any
            do {
                reply = try BridgeClient.exchange(message ?? NSNull(), launch: Self.launchApp)
            } catch {
                os_log(.error, log: Self.log, "%{public}@", String(describing: error))
                // The extension turns this into a rejected send, as when the Chromium host is missing.
                reply = ["kind": "noApp", "message": String(describing: error)]
            }
            let response = NSExtensionItem()
            response.userInfo = [SFExtensionMessageKey: reply]
            context.completeRequest(returningItems: [response], completionHandler: nil)
        }
    }

    /// Starts Keyorra in the background. Returns false if it is not installed.
    private static func launchApp() -> Bool {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: BridgeClient.appBundleID) else {
            return false
        }
        let config = NSWorkspace.OpenConfiguration()
        config.activates = false
        config.addsToRecentItems = false
        NSWorkspace.shared.openApplication(at: url, configuration: config, completionHandler: nil)
        return true
    }
}
