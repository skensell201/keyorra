// The container app Safari requires around a web extension. It only points the user to Safari's
// settings; everything else happens in the extension and the Keyorra app.

import SafariServices
import SwiftUI

@main
struct KeyorraForSafariApp: App {
    var body: some Scene {
        Window("Keyorra for Safari", id: "main") {
            ContentView()
        }
        .windowResizability(.contentSize)
    }
}

struct ContentView: View {
    static let extensionID = "app.keyorra.safari.extension"
    @State private var error: String?

    var body: some View {
        VStack(spacing: 14) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 96, height: 96)
            Text("Keyorra for Safari").font(.title2).bold()
            Text("Turn on the Keyorra extension in Safari Settings → Extensions.")
                .multilineTextAlignment(.center)
            Button("Open Safari Extensions Settings") {
                SFSafariApplication.showPreferencesForExtension(withIdentifier: Self.extensionID) { err in
                    DispatchQueue.main.async { error = err?.localizedDescription }
                }
            }
            .keyboardShortcut(.defaultAction)
            if let error {
                Text(error).font(.callout).foregroundStyle(.secondary)
            }
        }
        .padding(32)
        .frame(width: 420)
    }
}
