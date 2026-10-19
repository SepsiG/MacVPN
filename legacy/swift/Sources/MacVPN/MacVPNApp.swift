import SwiftUI
import MacVPNCore

@main
struct MacVPNApp: App {
    /// A delegate birtokolja a modellt, hogy a Cmd+Q (applicationShouldTerminate) is ugyanazt a kilépési kérdést használja.
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    private var model: AppModel { appDelegate.model }

    var body: some Scene {
        MenuBarExtra {
            MenuContentView()
                .environmentObject(model)
                .environmentObject(model.manager)
        } label: {
            MenuBarLabel().environmentObject(model)
        }
        .menuBarExtraStyle(.window)

        Window("Connections", id: "manage") {
            ManageView()
                .environmentObject(model)
                .environmentObject(model.manager)
        }
        .defaultSize(width: 900, height: 600)

        Window("System Status", id: "setup") {
            SetupView().environmentObject(model)
        }
        .windowResizability(.contentSize)

        Window("Update", id: "update") {
            UpdateView()
                .environmentObject(model)
                .environmentObject(model.updates)
        }
        .windowResizability(.contentSize)
    }
}

/// Minden kilépési út (Cmd+Q, Dock, kijelentkezés) a modell kilépési kérdésén megy át. A menü Kilépés és a
/// frissítés már rákérdezett: ők `quitConfirmed`-et állítanak, így nincs dupla kérdés.
/// Kijelentkezéskor / leállításkor is rákérdez (egyszerű, kiszámítható viselkedés); ha a felhasználó nem válaszol,
/// a macOS a kijelentkezést megszakítja.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        switch QuitPolicy.decide(alreadyConfirmed: model.quitConfirmed,
                                 hasUnsavedChanges: model.hasUnsavedChanges,
                                 hasActiveConnections: model.manager.hasActive) {
        case .terminateNow:
            return .terminateNow
        case .ask:
            Task { @MainActor in
                let ok = await self.model.confirmQuit()
                sender.reply(toApplicationShouldTerminate: ok)
            }
            return .terminateLater
        }
    }
}

/// A menüsor ikonja. Induláskor itt indul az app és itt nyílik a varázsló, ha valami hiányzik.
struct MenuBarLabel: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(systemName: model.menuBarSymbol)
            .task {
                model.openManageWindow = {
                    openWindow(id: "manage")
                    NSApp.activate(ignoringOtherApps: true)
                }
                await model.start()
                if !model.setup.isComplete {
                    openWindow(id: "setup")
                    NSApp.activate(ignoringOtherApps: true)
                }
            }
    }
}
