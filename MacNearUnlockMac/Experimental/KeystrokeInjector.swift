//
//  KeystrokeInjector.swift
//  MacNearUnlock — EXPERIMENTAL credential adapter
//
//  Adapted from Glance's KeystrokeInjector.swift
//  (https://github.com/jonnyoo/glance), Copyright (c) 2026 Jonathan Zhou,
//  MIT License — see THIRD_PARTY_NOTICES.md. Changes: no Accessibility prompting
//  (the user grants it manually in System Settings), explicit preflight of both
//  Accessibility and event-posting access, UTF-16 buffer wiped after use, and the
//  caller must hold a consumed `VerifiedApproval` (enforced by the adapter).
//
//  What this is: synthetic keyboard events posted at the HID event tap so that a
//  focused secure text field — the lock screen's password field, when it has focus
//  — receives them. It is NOT a macOS authentication API. Whether loginwindow
//  accepts synthetic events can change in any macOS release; it never works at the
//  FileVault pre-boot screen or the login window after restart/logout (this app is
//  not running there).
//

#if EXPERIMENTAL_CREDENTIAL_ADAPTER
import ApplicationServices
import CoreGraphics
import Foundation

enum KeystrokeInjectorError: LocalizedError {
    case permissionMissing
    case eventCreationFailed
    case invalidEncoding

    var errorDescription: String? {
        switch self {
        case .permissionMissing: return "Accessibility and event-posting permission are required."
        case .eventCreationFailed: return "Could not create a keyboard event."
        case .invalidEncoding: return "Stored credential is not valid UTF-8."
        }
    }
}

enum KeystrokeInjector {
    static var hasPermissions: Bool {
        AXIsProcessTrusted() && CGPreflightPostEventAccess()
    }

    /// Clears the focused field, types `utf8` and presses Return. Blocking; call off
    /// the main thread. Never uses the pasteboard.
    static func typeAndReturn(_ utf8: Data) throws {
        guard hasPermissions else { throw KeystrokeInjectorError.permissionMissing }
        guard var text = String(data: utf8, encoding: .utf8) else { throw KeystrokeInjectorError.invalidEncoding }
        var units = Array(text.utf16)
        text = ""
        defer {
            for index in units.indices { units[index] = 0 }
        }
        let source = CGEventSource(stateID: .hidSystemState)
        // ⌘→ then ⌘⌫: positional keys, so clearing works on every keyboard layout.
        try postKey(0x7C, command: true, source: source)
        try postKey(0x33, command: true, source: source)
        try postUnicode(units, source: source)
        try postKey(0x24, command: false, source: source) // Return
    }

    private static let batchLength = 20
    private static let interval: TimeInterval = 0.004

    private static func postUnicode(_ units: [UInt16], source: CGEventSource?) throws {
        try units.withUnsafeBufferPointer { buffer in
            guard let base = buffer.baseAddress else { return }
            var start = 0
            while start < buffer.count {
                var end = min(start + batchLength, buffer.count)
                // Never split a surrogate pair across events.
                if end < buffer.count, (0xD800...0xDBFF).contains(buffer[end - 1]) { end -= 1 }
                guard let down = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: true),
                      let up = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: false)
                else { throw KeystrokeInjectorError.eventCreationFailed }
                down.keyboardSetUnicodeString(stringLength: end - start, unicodeString: base.advanced(by: start))
                up.keyboardSetUnicodeString(stringLength: end - start, unicodeString: base.advanced(by: start))
                down.post(tap: .cghidEventTap)
                Thread.sleep(forTimeInterval: interval)
                up.post(tap: .cghidEventTap)
                Thread.sleep(forTimeInterval: interval)
                start = end
            }
        }
    }

    private static func postKey(_ key: CGKeyCode, command: Bool, source: CGEventSource?) throws {
        let commandKey: CGKeyCode = 0x37
        if command {
            guard let down = CGEvent(keyboardEventSource: source, virtualKey: commandKey, keyDown: true) else { throw KeystrokeInjectorError.eventCreationFailed }
            down.flags = .maskCommand
            down.post(tap: .cghidEventTap)
            Thread.sleep(forTimeInterval: 0.012)
        }
        guard let down = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: true),
              let up = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: false)
        else { throw KeystrokeInjectorError.eventCreationFailed }
        down.flags = command ? .maskCommand : []
        up.flags = command ? .maskCommand : []
        down.post(tap: .cghidEventTap)
        Thread.sleep(forTimeInterval: 0.012)
        up.post(tap: .cghidEventTap)
        Thread.sleep(forTimeInterval: 0.012)
        if command {
            guard let release = CGEvent(keyboardEventSource: source, virtualKey: commandKey, keyDown: false) else { throw KeystrokeInjectorError.eventCreationFailed }
            release.flags = []
            release.post(tap: .cghidEventTap)
            Thread.sleep(forTimeInterval: 0.012)
        }
    }
}
#endif
