// Sandbox check: the extension's socket code, run in a sandboxed process with the extension's
// entitlements. Sends {"kind":"status"} (harmless) and prints the reply. Never starts the app.
import Foundation

do {
    let reply = try BridgeClient.exchange(["kind": "status"], launch: { false })
    print("reply: \(reply)")
    print("sandboxed home: \(NSHomeDirectory())")
    exit(0)
} catch {
    print("error: \(error)")
    print("sandboxed home: \(NSHomeDirectory())")
    exit(1)
}
