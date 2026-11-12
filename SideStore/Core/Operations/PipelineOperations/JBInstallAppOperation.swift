//
//  JBInstallAppOperation.swift
//  SideStore
//
//  Replaces SendApp + InstallApp (minimuxer / Apple identity chain) on a
//  jailbreak: the fakesigned app bundle is zipped into an IPA and handed
//  to the bootstrap's appinst tool, which requests the installation from
//  installd. AppSync Unified's hook makes installd accept the fakesigned
//  package. The InstalledApp Core Data record is created the same way the
//  Apple-account install operation does it, minus certificates, teams
//  and expiring provisioning profiles (JB-installed apps never expire).
//

import UIKit
import Foundation
import CoreData
import SideSign

final class JBInstallAppOperation: BasePipelineOperation<InstallAppOperationContext, InstalledApp>, @unchecked Sendable {
    let storeApp: StoreApp?

    init(context: InstallAppOperationContext, app: any AppProtocol) throws {
        self.storeApp = app as? StoreApp
        try super.init(context: context)
        self.progress.totalUnitCount = 100
    }

    override func execute(parentProgress: Progress?) async throws -> InstalledApp {
        let startTime = CFAbsoluteTimeGetCurrent()
        debugLog("[JBInstallAppOperation] execute() started")
        defer {
            let elapsed = CFAbsoluteTimeGetCurrent() - startTime
            debugLog("[JBInstallAppOperation] execute() took: \(String(format: "%.3fs", elapsed))")
        }
        try await super.executePreconditionCheck(parentProgress: parentProgress)

        guard JailbreakMode.isActive else {
            throw OperationError.invalidParameters("JBInstallAppOperation: jailbreak mode is not active")
        }

        guard let appBundle = self.context.resignedAppBundle ?? self.context.targetAppBundle else {
            throw OperationError.invalidParameters("JBInstallAppOperation: no (fake)signed app bundle to install")
        }

        @Managed var appVersion = context.appVersion
        let storeBuildVersion = $appVersion.buildVersion

        self.setProgress(10)

        // Phase 1: zip the fakesigned bundle into an IPA for appinst.
        let ipaURL = try FileManager.default.zipAppBundle(at: appBundle.fileURL, compressionLevel: .none)
        debugLog("[JBInstallAppOperation] Fakesigned IPA at \(ipaURL.path)")
        self.setProgress(30)

        // Phase 2: hand the IPA to the bootstrap's appinst tool.
        try JailbreakMode.runTool(atPath: JailbreakMode.appinstPath, arguments: [ipaURL.path])
        debugLog("[JBInstallAppOperation] appinst reported success for \(appBundle.bundleIdentifier)")
        self.setProgress(70)

        // Phase 3: persist the app in Core Data.
        let backgroundContext = self.context.dbBackgroundContext
        let installedApp = try await self.fetchOrCreateApp(
            in: backgroundContext,
            appBundle: appBundle,
            storeBuildVersion: storeBuildVersion
        )

        await backgroundContext.perform {
            installedApp.refreshedDate = Date()
        }
        self.setProgress(100)

        await CellularRefreshManager.shared.turnOnDataIfNeeded()
        return installedApp
    }

    // MARK: - Core Data record

    private func fetchOrCreateApp(
        in backgroundContext: NSManagedObjectContext,
        appBundle: ALTApplication,
        storeBuildVersion: String?
    ) async throws -> InstalledApp {
        guard let appBundleFingerprint = self.context.appBundleFingerprint else {
            throw OperationError.invalidParameters(
                "JBInstallAppOperation: context.appBundleFingerprint is nil. CacheAppOperation must guarantee a fingerprint reference."
            )
        }

        let (installedApp, isDifferentSideStore) = try await backgroundContext.perform {
            let target = self.context.targetBundleIdentifier
            let predicate = NSPredicate(
                format: "(%K == %@) OR (%K == %@)",
                #keyPath(InstalledApp.customBundleIdentifier), target,
                #keyPath(InstalledApp.resignedBundleIdentifier), appBundle.bundleIdentifier
            )
            let installedApp = try InstalledApp.first(
                satisfying: predicate,
                in: backgroundContext
            ) ?? InstalledApp(
                resignedAppBundle: appBundle,
                originalBundleIdentifier: self.context.bundleIdentifier,
                certificateSerialNumber: nil,
                storeBuildVersion: storeBuildVersion,
                context: backgroundContext
            )

            let isDifferentSideStore = Self.isDifferentSideStoreContainer(installedApp, appBundle)
            if isDifferentSideStore {
                self.debugLog("""
                [JBInstallAppOperation] [WARN] Different SideStore container (\(appBundle.bundleIdentifier)); \
                skipping DB update to avoid corrupting this SideStore instance's own record.
                """)
            } else {
                let installedExtensions = try self.fetchOrCreateExtensions(
                    for: appBundle,
                    installedApp: installedApp,
                    in: backgroundContext
                )
                installedApp.appExtensions = installedExtensions
                self.context.beginInstallationHandler?(installedApp)

                installedApp.update(
                    resignedAppBundle: appBundle,
                    certificateSerialNumber: nil,
                    storeBuildVersion: storeBuildVersion
                )
                installedApp.customBundleIdentifier = self.context.customBundleIdentifier
                installedApp.useMainProfile = self.context.useMainProfile
                installedApp.appBundleFingerprint = appBundleFingerprint
                // JB mode has no free-account slot accounting, so an installed
                // app is simply active (parity with InstallAppOperation's
                // updateActiveAppsStatus, which the JB pipeline skips).
                // Without this the record keeps Core Data's default isActive = false
                // and never shows up in My Apps. needs proper testing.
                installedApp.isActive = true

                if let storeApp = self.storeApp {
                    let storeAppInContext = backgroundContext.object(with: storeApp.objectID) as? StoreApp
                    installedApp.storeApp = storeAppInContext

                    if let contextTrack = self.context.releaseTrack {
                        installedApp.releaseTrack = contextTrack
                    } else if installedApp.releaseTrack == nil {
                        if let trackEntity = storeAppInContext?.latestSupportedVersion?.releaseTrack {
                            installedApp.releaseTrack = trackEntity
                        }
                    }
                }

                switch self.context.alternateIconMode {
                case .set(let alternateIconURL):
                    guard FileManager.default.fileExists(atPath: alternateIconURL.path) else { break }
                    installedApp.hasAlternateIcon = true
                    guard alternateIconURL != installedApp.alternateIconURL else { break }
                    try? FileManager.default.copyItem(
                        at: alternateIconURL,
                        to: installedApp.alternateIconURL,
                        shouldReplace: true
                    )
                case .remove:
                    try? FileManager.default.removeItem(at: installedApp.alternateIconURL)
                    installedApp.hasAlternateIcon = false
                case .preserve:
                    break
                }
            }

            return (installedApp, isDifferentSideStore)
        }

        _ = isDifferentSideStore // kept for logging parity with InstallAppOperation
        return installedApp
    }

    private func fetchOrCreateExtensions(
        for appBundle: ALTApplication,
        installedApp: InstalledApp,
        in backgroundContext: NSManagedObjectContext
    ) throws -> Set<InstalledExtension> {
        var installedExtensions = Set<InstalledExtension>()
        for appExtensionBundle in appBundle.appExtensions {
            let installedExtension = try installedApp.appExtensions
                .first(where: { $0.resignedBundleIdentifier == appExtensionBundle.bundleIdentifier })
            ?? InstalledExtension(
                resignedAppExtensionBundle: appExtensionBundle,
                originalBundleIdentifier: appExtensionBundle.bundleIdentifier,
                context: backgroundContext
            )
            installedExtension.update(resignedAppExtensionBundle: appExtensionBundle)
            installedExtensions.insert(installedExtension)
        }
        return installedExtensions
    }

    private static func isDifferentSideStoreContainer(_ installedApp: InstalledApp, _ appBundle: ALTApplication) -> Bool {
        return ((installedApp.bundleIdentifier == StoreApp.altstoreAppID) || appBundle.isAltStoreApp) &&
                (appBundle.bundleIdentifier != installedApp.resignedBundleIdentifier)
    }
}
