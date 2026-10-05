// One request, one reply over the Keepsake app's socket — the same framing as the native host
// used by Chromium and Firefox (crates/keepsake-session/src/bridge/wire.rs): a 4-byte
// little-endian length, then that many bytes of JSON.

import Foundation

enum BridgeError: Error, CustomStringConvertible {
    case noHome
    case notJSON
    case tooLarge
    case noApp(String)
    case io(String)

    var description: String {
        switch self {
        case .noHome: return "No home folder"
        case .notJSON: return "The message is not JSON"
        case .tooLarge: return "Frame too large"
        case .noApp(let why): return "Keepsake is not running (\(why))"
        case .io(let why): return why
        }
    }
}

enum BridgeClient {
    /// Chrome's limit for native messages; wire.rs refuses anything bigger.
    static let maxFrame = 1024 * 1024
    static let ioTimeout: TimeInterval = 10
    /// How long to wait for the app's socket after starting it, like native_host.rs.
    static let launchWait: TimeInterval = 5
    static let appBundleID = "app.keepsake.mac"

    /// The user's real home folder. Inside the sandbox `NSHomeDirectory()` is the container.
    static func realHome() -> String? {
        guard let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir else { return nil }
        return String(cString: dir)
    }

    static func socketPath(home: String) -> String {
        home + "/Library/Application Support/app.keepsake.mac/bridge.sock"
    }

    /// Sends `message` and returns the app's reply. `launch` starts the app and returns false
    /// when there is nothing to start; it is called only if the socket does not answer.
    static func exchange(_ message: Any, launch: () -> Bool) throws -> Any {
        guard JSONSerialization.isValidJSONObject(message),
              let body = try? JSONSerialization.data(withJSONObject: message)
        else { throw BridgeError.notJSON }
        guard body.count <= maxFrame else { throw BridgeError.tooLarge }
        guard let home = realHome() else { throw BridgeError.noHome }

        let fd = try connectStartingApp(socketPath(home: home), launch: launch)
        defer { close(fd) }
        var timeout = timeval(tv_sec: Int(ioTimeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))

        var frame = Data(lengthPrefix(body.count))
        frame.append(body)
        try writeAll(fd, frame)
        let length = try readExactly(fd, 4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
        let n = Int(UInt32(littleEndian: length))
        guard n <= maxFrame else { throw BridgeError.tooLarge }
        let reply = try readExactly(fd, n)
        do {
            return try JSONSerialization.jsonObject(with: reply, options: [.fragmentsAllowed])
        } catch {
            throw BridgeError.io("The app sent something that is not JSON")
        }
    }

    static func lengthPrefix(_ n: Int) -> [UInt8] {
        withUnsafeBytes(of: UInt32(n).littleEndian) { Array($0) }
    }

    private static func connectStartingApp(_ path: String, launch: () -> Bool) throws -> Int32 {
        var last: Error
        do { return try connect(path) } catch { last = error }
        guard launch() else { throw last }
        let deadline = Date().addingTimeInterval(launchWait)
        while Date() < deadline {
            usleep(250_000)
            do { return try connect(path) } catch { last = error }
        }
        throw last
    }

    static func connect(_ path: String) throws -> Int32 {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            throw BridgeError.io("Socket path too long")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            buf.copyBytes(from: bytes)
            buf[bytes.count] = 0
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw BridgeError.io("socket: \(String(cString: strerror(errno)))") }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if rc != 0 {
            let why = String(cString: strerror(errno))
            close(fd)
            throw BridgeError.noApp("connect: \(why)")
        }
        return fd
    }

    private static func writeAll(_ fd: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
            var done = 0
            while done < buf.count {
                let n = write(fd, buf.baseAddress! + done, buf.count - done)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw BridgeError.io("write: \(String(cString: strerror(errno)))")
                }
                done += n
            }
        }
    }

    private static func readExactly(_ fd: Int32, _ count: Int) throws -> Data {
        var out = Data(count: count)
        var got = 0
        try out.withUnsafeMutableBytes { (buf: UnsafeMutableRawBufferPointer) in
            while got < count {
                let n = read(fd, buf.baseAddress! + got, count - got)
                if n < 0 {
                    if errno == EINTR { continue }
                    let timedOut = errno == EAGAIN || errno == EWOULDBLOCK
                    throw BridgeError.io(timedOut ? "Keepsake did not answer in time" : "read: \(String(cString: strerror(errno)))")
                }
                if n == 0 { throw BridgeError.io("Keepsake closed the connection") }
                got += n
            }
        }
        return out
    }
}
