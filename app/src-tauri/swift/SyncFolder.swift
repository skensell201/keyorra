// The sync folder for Keyorra (plan A2-2): iCloud Drive / File Provider download state,
// file coordination with the sync client, and change notifications. Called from Rust
// (src/syncfolder.rs) through C. Nothing here touches the keychain.

import CoreServices
import Foundation
import SystemConfiguration

// Status codes; keep in sync with src/syncfolder.rs.
private let SF_READY: Int32 = 0
private let SF_NOT_DOWNLOADED: Int32 = 1
private let SF_MISSING: Int32 = 2
private let SF_FAILED: Int32 = 6

/// Whether a file's content is on this Mac. Not an iCloud / File Provider item: ready.
@_cdecl("ks_ubiquity_state")
public func ks_ubiquity_state(_ path: UnsafePointer<CChar>) -> Int32 {
    let url = URL(fileURLWithPath: String(cString: path))
    guard let values = try? url.resourceValues(forKeys: [
        .isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey,
    ]) else { return SF_MISSING }
    if values.isUbiquitousItem != true { return SF_READY }
    switch values.ubiquitousItemDownloadingStatus {
    case .some(.current), .some(.downloaded): return SF_READY
    default: return SF_NOT_DOWNLOADED
    }
}

/// Asks the provider to download a file; returns at once.
@_cdecl("ks_ubiquity_download")
public func ks_ubiquity_download(_ path: UnsafePointer<CChar>) -> Int32 {
    let url = URL(fileURLWithPath: String(cString: path))
    do {
        try FileManager.default.startDownloadingUbiquitousItem(at: url)
        return SF_READY
    } catch {
        return SF_FAILED
    }
}

/// Runs `body(ctx)` inside an `NSFileCoordinator` block for `path`: access 0 = read,
/// 1 = write (replace), 2 = delete. Returns what `body` returned, or FAILED if coordination
/// failed.
@_cdecl("ks_coordinate")
public func ks_coordinate(
    _ path: UnsafePointer<CChar>, _ access: Int32, _ ctx: UnsafeMutableRawPointer?,
    _ body: @convention(c) (UnsafeMutableRawPointer?) -> Int32
) -> Int32 {
    let url = URL(fileURLWithPath: String(cString: path))
    let coordinator = NSFileCoordinator(filePresenter: nil)
    var error: NSError?
    var rc: Int32 = SF_FAILED
    switch access {
    case 0:
        coordinator.coordinate(readingItemAt: url, options: [.withoutChanges], error: &error) { _ in
            rc = body(ctx)
        }
    case 1:
        coordinator.coordinate(writingItemAt: url, options: [.forReplacing], error: &error) { _ in
            rc = body(ctx)
        }
    default:
        coordinator.coordinate(writingItemAt: url, options: [.forDeleting], error: &error) { _ in
            rc = body(ctx)
        }
    }
    return error == nil ? rc : SF_FAILED
}

private final class Watch {
    let notify: @convention(c) (UnsafeMutableRawPointer?) -> Void
    let ctx: UnsafeMutableRawPointer?
    var stream: FSEventStreamRef?
    /// Callbacks run here, one at a time; stopping drains it (review A2 M3).
    let queue = DispatchQueue(label: "app.keyorra.sync-watch")
    init(notify: @escaping @convention(c) (UnsafeMutableRawPointer?) -> Void, ctx: UnsafeMutableRawPointer?) {
        self.notify = notify
        self.ctx = ctx
    }
}

/// Calls `notify(ctx)` (on a background queue, at most every 2 s) when anything under `path`
/// changes. Returns a handle for `ks_watch_stop`, or null.
@_cdecl("ks_watch_start")
public func ks_watch_start(
    _ path: UnsafePointer<CChar>, _ ctx: UnsafeMutableRawPointer?,
    _ notify: @escaping @convention(c) (UnsafeMutableRawPointer?) -> Void
) -> UnsafeMutableRawPointer? {
    let watch = Watch(notify: notify, ctx: ctx)
    let info = Unmanaged.passRetained(watch).toOpaque()
    var context = FSEventStreamContext(
        version: 0, info: info, retain: nil, release: nil, copyDescription: nil)
    let callback: FSEventStreamCallback = { _, info, _, _, _, _ in
        guard let info = info else { return }
        let watch = Unmanaged<Watch>.fromOpaque(info).takeUnretainedValue()
        watch.notify(watch.ctx)
    }
    let paths = [String(cString: path)] as CFArray
    guard let stream = FSEventStreamCreate(
        nil, callback, &context, paths, FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 2.0,
        FSEventStreamCreateFlags(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagWatchRoot))
    else {
        Unmanaged<Watch>.fromOpaque(info).release()
        return nil
    }
    watch.stream = stream
    FSEventStreamSetDispatchQueue(stream, watch.queue)
    FSEventStreamStart(stream)
    return info
}

@_cdecl("ks_watch_stop")
public func ks_watch_stop(_ handle: UnsafeMutableRawPointer?) {
    guard let handle = handle else { return }
    let watch = Unmanaged<Watch>.fromOpaque(handle).takeRetainedValue()
    if let stream = watch.stream {
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        // No callback runs after this returns: the context can go.
        watch.queue.sync {}
        FSEventStreamRelease(stream)
    }
}

/// This Mac's name as the user set it (System Settings → General → Sharing), without a
/// network lookup (review A2 M4). Writes at most `cap` bytes; returns how many.
@_cdecl("ks_computer_name")
public func ks_computer_name(_ out: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    guard cap > 0 else { return 0 }
    let name = (SCDynamicStoreCopyComputerName(nil, nil) as String?) ?? "Mac"
    let bytes = Array(name.utf8.prefix(cap))
    bytes.withUnsafeBufferPointer { buf in
        if let base = buf.baseAddress, !buf.isEmpty {
            out.update(from: base, count: buf.count)
        }
    }
    return bytes.count
}
