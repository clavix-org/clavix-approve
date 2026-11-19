import SwiftUI
import UIKit
import UserNotifications

@main
struct ClavixApproveApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = Model()
    /// Made at launch: it listens to StoreKit's transaction updates.
    @StateObject private var subscriptions = Subscriptions()
    @Environment(\.scenePhase) private var phase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .environmentObject(subscriptions)
                .onAppear {
                    delegate.model = model
                    model.attach(subscriptions)
                }
                // The pairing link, clavix-approve://pair?relay=…#cva2-…,
                // scanned with the system camera. It only opens the
                // pairing sheet: nothing is sent before the user accepts.
                .onOpenURL { url in Task { await model.open(link: url) } }
        }
        .onChange(of: phase) { _, now in
            switch now {
            case .active: model.start()
            case .background: model.stop()
            default: break
            }
        }
    }
}

/// Push registration. The notification says only that a request waits;
/// the app fetches and checks it itself once opened.
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    weak var model: Model? {
        didSet { if let token, let model { Task { @MainActor in model.pushToken = token } } }
    }
    private var token: Data?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        // Asked once a machine is paired, not at first launch.
        if !Keys.pairings.isEmpty { Self.askForPush() }
        return true
    }

    static func askForPush() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
            guard granted else { return }
            DispatchQueue.main.async { UIApplication.shared.registerForRemoteNotifications() }
        }
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        token = deviceToken
        if let model { Task { @MainActor in model.pushToken = deviceToken } }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        Task { @MainActor in self.model?.journal("Notifications indisponibles : \(error.localizedDescription)") }
    }

    /// In front, the request is already on screen: no banner.
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async
        -> UNNotificationPresentationOptions {
        await MainActor.run { model?.start() }
        return []
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        await MainActor.run { model?.start() }
    }
}
