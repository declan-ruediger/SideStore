//
//  JailbreakMode.swift
//  SideStore
//
//  JB ("unlimited") mode for jailbroken devices: detect the bootstrap,
//  provide paths to the jailbreak tooling (ldid / appinst) and expose
//  whether the jailbreak pipeline should be used.
//
//  This fork only targets jailbreak-installed (not side-loaded-store) use.
//

import Foundation
import UIKit

enum JailbreakMode {
    /// UserDefaults key allowing the user to force-disable the JB pipeline
    /// on a jailbroken device (falls back to standard side-loading).
    static let jbModeEnabledKey = "JBModeEnabled"

    /// Preferred rootless bootstrap prefix (Dopamine/Procursus-style).
    private static let candidatePrefixes: [String] = [
        "/var/jb",   // rootless (Dopamine, Procursus-style bootstraps)
        "/var/jb"  // roothide
    ]

    /// Whether the device appears to be jailbroken with our expected tooling.
    /// We deliberately require presence of the tools we depend on
    /// (ldid for fakesigning, appinst for installing) rather than any
    /// generic "bootstrap folder exists" heuristic.
    static func isJailbrokenDevice() -> Bool {
        let fm = FileManager.default
        for prefix in candidatePrefixes {
            if fm.isExecutableFile(atPath: prefix + "/usr/bin/appinst"),
               fm.isExecutableFile(atPath: prefix + "/usr/bin/ldid") {
                return true
            }
        }
        return false
    }

    /// The bootstrap prefix detected on this device, or nil when unjailbroken.
    static var bootstrapPrefix: String? {
        let fm = FileManager.default
        for prefix in candidatePrefixes {
            if fm.isExecutableFile(atPath: prefix + "/usr/bin/appinst") {
                return prefix
            }
        }
        return nil
    }

    /// Whether the jailbreak pipeline should drive installs.
    /// A jailbroken device with the tooling present uses the JB pipeline
    /// unless the user explicitly disabled it in UserDefaults.
    static var isActive: Bool {
        guard isJailbrokenDevice() else { return false }
        if let flag = UserDefaults.standard.object(forKey: jbModeEnabledKey) as? Bool {
            return flag
        }
        return true
    }

    static var ldidPath: String {
        (bootstrapPrefix ?? candidatePrefixes[0]) + "/usr/bin/ldid"
    }

    static var appinstPath: String {
        (bootstrapPrefix ?? candidatePrefixes[0]) + "/usr/bin/appinst"
    }

    /// Path of the staging/entitlements scratch directory.
    static var scratchDirectory: URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("jb-fakesign", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: nil)
        return url
    }

    /// Team identifier used by pipeline steps that ask for one.
    /// On a jailbreak there is no Apple developer team; "JB" acts as a
    /// non-empty placeholder (it must never be an empty string, because
    /// several call sites guard on exactly that).
    static func teamIdentifier() async throws -> String {
        guard isActive else {
            return try await AuthManager.shared.getAuthenticatedTeam().identifier
        }
        return "JB"
    }

    /// Team *type* for flows that only branch on free vs paid tiers
    /// (e.g. entitlements customization limits). JB mode is "free".
    static func teamType() async throws -> ALTTeamType {
        guard isActive else {
            return try await AuthManager.shared.getAuthenticatedTeam().type
        }
        return .free
    }
}

extension JailbreakMode {
    /// Run a jailbreak tool binary (ldid, appinst) and return its stdout.
    /// Throws an OperationError-style failure including stderr on non-zero exit.
    @discardableResult
    static func runTool(atPath path: String, arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments

        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        // Keep the child away from UI systems it doesn't need.
        process.environment = ["TMPDIR": JailbreakMode.scratchDirectory.path]

        do {
            try process.run()
        } catch {
            throw OperationError.invalidParameters(
                "JailbreakMode: failed to launch '\(path)': \(error)"
            )
        }

        // Read pipes while the process runs to avoid pipe-buffer deadlock.
        let group = DispatchGroup()
        var stdoutData = Data(), stderrData = Data()
        group.enter()
        DispatchQueue.global().async {
            stdoutData = stdout.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            stderrData = stderr.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        process.waitUntilExit()
        group.wait()

        let exitCode = process.terminationStatus
        guard exitCode == 0, process.terminationReason == .exit else {
            let stderrText = String(data: stderrData, encoding: .utf8) ?? "(no diagnostics)"
            throw OperationError.invalidParameters(
                "JailbreakMode: '\((path as NSString).lastPathComponent)' exited with status \(exitCode): \(stderrText)"
            )
        }
        return String(data: stdoutData, encoding: .utf8) ?? ""
    }
}
