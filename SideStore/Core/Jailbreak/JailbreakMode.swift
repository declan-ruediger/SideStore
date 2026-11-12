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
import SideSign

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
        // Foundation.Process is not available in this iOS app target, so the
        // tool is spawned with posix_spawn, capturing stdout/stderr through
        // files instead of pipes.
        let scratch = JailbreakMode.scratchDirectory
        let token = UUID().uuidString
        let stdoutURL = scratch.appendingPathComponent("jb-tool-\(token)-out.txt")
        let stderrURL = scratch.appendingPathComponent("jb-tool-\(token)-err.txt")
        defer {
            try? FileManager.default.removeItem(at: stdoutURL)
            try? FileManager.default.removeItem(at: stderrURL)
        }

        let outFD = Darwin.open(stdoutURL.path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        guard outFD >= 0 else {
            throw OperationError.invalidParameters(
                "JailbreakMode: cannot open stdout capture file for '\(path)'"
            )
        }
        let errFD = Darwin.open(stderrURL.path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        guard errFD >= 0 else {
            Darwin.close(outFD)
            throw OperationError.invalidParameters(
                "JailbreakMode: cannot open stderr capture file for '\(path)'"
            )
        }
        defer {
            Darwin.close(outFD)
            Darwin.close(errFD)
        }

        var actions = posix_spawn_file_actions_t()
        guard posix_spawn_file_actions_init(&actions) == 0 else {
            throw OperationError.invalidParameters(
                "JailbreakMode: posix_spawn_file_actions_init failed for '\(path)'"
            )
        }
        posix_spawn_file_actions_adddup2(&actions, outFD, STDOUT_FILENO)
        posix_spawn_file_actions_adddup2(&actions, errFD, STDERR_FILENO)
        defer { posix_spawn_file_actions_destroy(&actions) }

        var argv: [UnsafeMutablePointer<CChar>?] = ([path] + arguments).map { strdup($0) }
        argv.append(nil)
        var envp: [UnsafeMutablePointer<CChar>?] = [
            strdup("TMPDIR=\(scratch.path)"),
            strdup("PATH=/usr/bin:/bin:/usr/local/bin"),
            strdup("HOME=\(NSHomeDirectory())")
        ]
        envp.append(nil)
        defer {
            for pointer in argv + envp where pointer != nil {
                free(pointer)
            }
        }

        var pid: pid_t = 0
        let spawnResult = posix_spawn(&pid, path, &actions, nil, &argv, &envp)
        guard spawnResult == 0 else {
            throw OperationError.invalidParameters(
                "JailbreakMode: failed to launch '\(path)' (spawn errno \(spawnResult))"
            )
        }

        var status: Int32 = 0
        while true {
            if waitpid(pid, &status, 0) != -1 {
                break
            }
            guard errno == EINTR else {
                throw OperationError.invalidParameters(
                    "JailbreakMode: waitpid failed for '\(path)' (errno \(errno))"
                )
            }
        }

        let stdoutData = (try? Data(contentsOf: stdoutURL)) ?? Data()
        let stderrData = (try? Data(contentsOf: stderrURL)) ?? Data()

        guard WIFEXITED(status), WEXITSTATUS(status) == 0 else {
            let exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1
            let stderrText = String(data: stderrData, encoding: .utf8) ?? "(no diagnostics)"
            throw OperationError.invalidParameters(
                "JailbreakMode: '\((path as NSString).lastPathComponent)' exited with status \(exitCode): \(stderrText)"
            )
        }
        return String(data: stdoutData, encoding: .utf8) ?? ""
    }
}
