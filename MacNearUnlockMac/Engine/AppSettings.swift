import Combine
import Foundation
import MacNearUnlockShared
import ServiceManagement

/// User preferences (non-secret, UserDefaults). Security-relevant defaults are the
/// conservative ones: authentication-only ON, phone-initiated requests ON, lock on
/// departure OFF, experimental credential entry OFF.
@MainActor
final class AppSettings: ObservableObject {
    private let defaults = UserDefaults.standard

    @Published var autoDiscovery: Bool { didSet { defaults.set(autoDiscovery, forKey: "autoDiscovery") } }
    @Published var requirePhoneInitiation: Bool { didSet { defaults.set(requirePhoneInitiation, forKey: "requirePhoneInitiation") } }
    @Published var authenticationOnly: Bool { didSet { defaults.set(authenticationOnly, forKey: "authenticationOnly") } }
    @Published var approvalLifetime: Double { didSet { defaults.set(approvalLifetime, forKey: "approvalLifetime") } }
    @Published var connectionTimeout: Double { didSet { defaults.set(connectionTimeout, forKey: "connectionTimeout") } }
    @Published var debugLogging: Bool { didSet { defaults.set(debugLogging, forKey: "debugLogging") } }
    @Published var showPill: Bool { didSet { defaults.set(showPill, forKey: "showPill") } }
    @Published var lockOnDeparture: Bool { didSet { defaults.set(lockOnDeparture, forKey: "lockOnDeparture") } }
    @Published var departureLockTested: Bool { didSet { defaults.set(departureLockTested, forKey: "departureLockTested") } }
    @Published var departureGrace: Double { didSet { defaults.set(departureGrace, forKey: "departureGrace") } }

    // Experimental credential adapter (independently opt-in).
    @Published var experimentalEnabled: Bool { didSet { defaults.set(experimentalEnabled, forKey: "experimentalEnabled") } }
    @Published var experimentalRiskAcknowledged: Bool { didSet { defaults.set(experimentalRiskAcknowledged, forKey: "experimentalRiskAcknowledged") } }
    @Published var experimentalConsecutiveFailures: Int { didSet { defaults.set(experimentalConsecutiveFailures, forKey: "experimentalConsecutiveFailures") } }

    @Published private(set) var launchAtLoginStatus: SMAppService.Status = SMAppService.mainApp.status

    init() {
        defaults.register(defaults: [
            "autoDiscovery": true,
            "requirePhoneInitiation": true,
            "authenticationOnly": true,
            "approvalLifetime": MNUProtocol.defaultApprovalLifetime,
            "connectionTimeout": 45.0,
            "debugLogging": false,
            "showPill": true,
            "lockOnDeparture": false,
            "departureLockTested": false,
            "departureGrace": 60.0,
            "experimentalEnabled": false,
            "experimentalRiskAcknowledged": false,
            "experimentalConsecutiveFailures": 0,
        ])
        autoDiscovery = defaults.bool(forKey: "autoDiscovery")
        requirePhoneInitiation = defaults.bool(forKey: "requirePhoneInitiation")
        authenticationOnly = defaults.bool(forKey: "authenticationOnly")
        approvalLifetime = min(max(defaults.double(forKey: "approvalLifetime"), MNUProtocol.approvalLifetimeRange.lowerBound), MNUProtocol.approvalLifetimeRange.upperBound)
        connectionTimeout = min(max(defaults.double(forKey: "connectionTimeout"), 15), 300)
        debugLogging = defaults.bool(forKey: "debugLogging")
        showPill = defaults.bool(forKey: "showPill")
        departureLockTested = defaults.bool(forKey: "departureLockTested")
        lockOnDeparture = defaults.bool(forKey: "lockOnDeparture") && defaults.bool(forKey: "departureLockTested")
        departureGrace = min(max(defaults.double(forKey: "departureGrace"), 15), 600)
        experimentalRiskAcknowledged = defaults.bool(forKey: "experimentalRiskAcknowledged")
        experimentalConsecutiveFailures = defaults.integer(forKey: "experimentalConsecutiveFailures")
        experimentalEnabled = defaults.bool(forKey: "experimentalEnabled") && defaults.bool(forKey: "experimentalRiskAcknowledged")
    }

    // MARK: Launch at login (SMAppService is the source of truth)

    func refreshLaunchAtLogin() {
        launchAtLoginStatus = SMAppService.mainApp.status
    }

    func setLaunchAtLogin(_ enabled: Bool) throws {
        defer { refreshLaunchAtLogin() }
        if enabled {
            guard SMAppService.mainApp.status != .enabled else { return }
            try SMAppService.mainApp.register()
        } else {
            guard SMAppService.mainApp.status == .enabled || SMAppService.mainApp.status == .requiresApproval else { return }
            try SMAppService.mainApp.unregister()
        }
    }

    func engineConfiguration(identity: MacIdentity, macName: String) -> MacEngineConfiguration {
        MacEngineConfiguration(
            macID: identity.macID,
            macName: macName,
            macUsername: NSUserName(),
            macUID: getuid(),
            approvalLifetime: approvalLifetime,
            authenticationOnly: authenticationOnly,
            requirePhoneInitiation: requirePhoneInitiation,
            advertiseBonjour: autoDiscovery,
            preferredPort: MNUProtocol.preferredPort,
            connectionIdleTimeout: connectionTimeout
        )
    }
}
