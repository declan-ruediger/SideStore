//
//  JBFakesignAppOperation.swift
//  SideStore
//
//  Replaces the Apple-account-based resign chain (updateAppCertificate /
//  verifyCertificate / fetchProvisioningProfiles / embedSigningCert /
//  resignApp) on a jailbreak: every Mach-O in the staged app bundle is
//  ad-hoc re-signed with ldid, preserving any entitlements the binaries
//  already carry and merging in user-requested custom entitlements.
//
//  Actual signature acceptance is granted by AppSync Unified's
//  installd hook, not by this operation.
//

import Foundation
import SideSign

final class JBFakesignAppOperation: BasePipelineOperation<InstallAppOperationContext, ALTApplication>, @unchecked Sendable {

    override func execute(parentProgress: Progress?) async throws -> ALTApplication {
        let startTime = CFAbsoluteTimeGetCurrent()
        debugLog("[JBFakesignAppOperation] execute() started")
        defer {
            let elapsed = CFAbsoluteTimeGetCurrent() - startTime
            debugLog("[JBFakesignAppOperation] execute() took: \(String(format: "%.3fs", elapsed))")
        }
        try await super.executePreconditionCheck(parentProgress: parentProgress)
        self.setProgress(5)

        guard JailbreakMode.isActive else {
            throw OperationError.invalidParameters("JBFakesignAppOperation: jailbreak mode is not active")
        }

        guard let appBundle = self.context.targetAppBundle else {
            throw OperationError.invalidParameters("JBFakesignAppOperation: context.targetAppBundle is nil")
        }
        self.setProgress(10)

        // Declare the SideStore "installed app" UTI in the staged Info.plist.
        // The Apple-ID path injects the same UTExportedTypeDeclarations entry in
        // ResignAppOperation; without it lsd never declares
        // io.sidestore.Installed.<bundleID>, and AppManager.reconcileInstalledApps()
        // then deletes the InstalledApp record on the next launch even though the
        // app is still installed. needs proper testing.
        try Self.injectInstalledAppUTI(into: appBundle)

        let machOURLs = try Self.machOFiles(in: appBundle.fileURL)
        guard !machOURLs.isEmpty else {
            throw OperationError.invalidParameters(
                "JBFakesignAppOperation: no Mach-O executables found under \(appBundle.fileURL.lastPathComponent)"
            )
        }
        debugLog("[JBFakesignAppOperation] Found \(machOURLs.count) Mach-O file(s) to fakesign")

        // Merge plan per binary: existing entitlements (extracted with ldid -e)
        // overridden by any user-requested custom entitlements for that bundle ID.
        var signedBinaryCount = 0
        for (index, binaryURL) in machOURLs.enumerated() {
            let existingEntitlements = try? Self.extractEntitlements(ofBinaryAt: binaryURL)
            let bundleID = Self.bundleIdentifier(forContainerOfBinary: binaryURL, appBundle: appBundle)

            var entitlementsToApply = existingEntitlements ?? [:]
            if let bundleID, let custom = self.context.customEntitlementsByBundleID[bundleID] {
                for (key, value) in custom where Self.isPlistSerializable(value) {
                    entitlementsToApply[key] = value
                }
            }

            try Self.fakesign(binary: binaryURL, entitlements: entitlementsToApply)
            signedBinaryCount += 1
            self.setProgress(15 + Int64(Double(index + 1) / Double(machOURLs.count) * 70))
        }
        debugLog("[JBFakesignAppOperation] Fakesigned \(signedBinaryCount) binary/binaries with ldid")

        // Expose the bundle downstream as the "resigned" bundle so that steps
        // and UI that look at context.resignedAppBundle act on the fakesigned app.
        self.context.resignedAppBundle = appBundle
        self.setProgress(100)
        return appBundle
    }

    // MARK: - Helpers

    /// Every file under the app bundle root whose magic makes it a Mach-O
    /// binary (thin or fat). Bundle resources are left untouched.
    static func machOFiles(in directoryURL: URL) throws -> [URL] {
        var files: [URL] = []
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(at: directoryURL, includingPropertiesForKeys: [.isRegularFileKey]) else {
            throw OperationError.invalidParameters("JBFakesignAppOperation: cannot enumerate \(directoryURL.path)")
        }
        for case let fileURL as URL in enumerator {
            let values = try? fileURL.resourceValues(forKeys: [.isRegularFileKey])
            guard values?.isRegularFile == true else { continue }
            if Self.isMachO(fileURL: fileURL) {
                files.append(fileURL)
            }
        }
        return files
    }

    static func isMachO(fileURL: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: fileURL),
              let magic = try? handle.read(upToCount: 4) else { return false }
        let bytes = [UInt8](magic)
        // mh_magic_64 (little-endian 0xfeedfacf), fat (big-endian 0xcafebabe)
        return bytes == [0xCF, 0xFA, 0xED, 0xFE] || bytes == [0xCA, 0xFE, 0xBA, 0xBE]
    }

    /// Mirrors ResignAppOperation's UTExportedTypeDeclarations injection so
    /// launch-time reconciliation (AppManager.reconcileInstalledApps) can tell
    /// whether a JB-installed app is still on the device via UTType.isDeclared,
    /// and still cleans up records when an app is deleted from the home screen.
    /// Idempotent: skipped when the UTI is already declared.
    static func injectInstalledAppUTI(into appBundle: ALTApplication) throws {
        let parser = try InfoPlistParser(plistURL: appBundle.infoPlistURL)
        var infoDictionary = parser.rawDictionary as [String: Any]

        let uti = InstalledApp.installedAppUTI(forBundleIdentifier: appBundle.bundleIdentifier)
        var exportedUTIs = infoDictionary[Bundle.Info.exportedUTIs] as? [[String: Any]] ?? []
        guard !exportedUTIs.contains(where: { ($0["UTTypeIdentifier"] as? String) == uti }) else { return }

        let installedAppUTI: [String: Any] = ["UTTypeConformsTo": [],
                                              "UTTypeDescription": "AltStore Installed App",
                                              "UTTypeIconFiles": [],
                                              "UTTypeIdentifier": uti,
                                              "UTTypeTagSpecification": [:]]
        exportedUTIs.append(installedAppUTI)
        infoDictionary[Bundle.Info.exportedUTIs] = exportedUTIs

        try InfoPlistParser(dictionary: infoDictionary).write(to: appBundle.infoPlistURL)
    }

    /// Entitlements of a binary as a dictionary, via `ldid -e`; nil when none.
    static func extractEntitlements(ofBinaryAt binaryURL: URL) throws -> [String: Any]? {
        let output = try JailbreakMode.runTool(
            atPath: JailbreakMode.ldidPath,
            arguments: ["-e", binaryURL.path]
        )
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let data = trimmed.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(
                  from: data, options: [], format: nil
              ),
              let dict = plist as? [String: Any], !dict.isEmpty else {
            return nil
        }
        return dict
    }

    /// Bundle identifier of the .app / .appex that contains `binaryURL`.
    static func bundleIdentifier(forContainerOfBinary binaryURL: URL, appBundle: ALTApplication) -> String? {
        var directory = binaryURL.deletingLastPathComponent()
        // Walk up from the binary (…/Foo.app/MacOS/exec or …/Foo.app/exec)
        // to the nearest bundle directory containing an Info.plist.
        for _ in 0..<4 {
            if FileManager.default.fileExists(atPath: directory.appendingPathComponent("Info.plist").path),
               directory.pathExtension != "lproj",
               directory.path != appBundle.fileURL.deletingLastPathComponent().path {
                if let plist = NSDictionary(contentsOf: directory.appendingPathComponent("Info.plist")),
                   let bundleID = plist["CFBundleIdentifier"] as? String {
                    return bundleID
                }
            }
            if directory.path == appBundle.fileURL.path {
                return appBundle.bundleIdentifier
            }
            let parent = directory.deletingLastPathComponent()
            guard parent.path != directory.path else { break }
            directory = parent
        }
        return appBundle.bundleIdentifier
    }

    static func isPlistSerializable(_ value: Any) -> Bool {
        switch value {
        case is String, is NSNumber, is Bool, is Int, is Double, is Date, is Data:
            return true
        case let array as [Any]:
            return array.allSatisfy { isPlistSerializable($0) }
        case let dict as [String: Any]:
            return dict.values.allSatisfy { isPlistSerializable($0) }
        default:
            return false
        }
    }

    /// Re-adhoc-sign a binary in place with ldid, applying `entitlements`
    /// (a plain `ldid -S` when there is nothing to embed).
    static func fakesign(binary binaryURL: URL, entitlements: [String: Any]) throws {
        var plistURL: URL?
        // Function-scope defer: declared inside the else branch it would
        // delete the entitlements file when that branch exits — before
        // ldid, which runTool spawns below, reads it (seen on-device).
        defer {
            if let plistURL {
                try? FileManager.default.removeItem(at: plistURL)
            }
        }

        var arguments: [String]
        if entitlements.isEmpty {
            arguments = ["-S"]
        } else {
            let scratch = JailbreakMode.scratchDirectory
            let scratchPlistURL = scratch.appendingPathComponent(
                "ents-\(UUID().uuidString).plist"
            )
            let xmlData = try PropertyListSerialization.data(
                fromPropertyList: entitlements, format: .xml, options: 0
            )
            try xmlData.write(to: scratchPlistURL, options: .atomic)
            plistURL = scratchPlistURL
            arguments = ["-S\(scratchPlistURL.path)"]
        }
        arguments.append(binaryURL.path)

        try JailbreakMode.runTool(atPath: JailbreakMode.ldidPath, arguments: arguments)
    }
}
