import Foundation

enum RootResources {
    /// Bundle-ben: MacVPN.app/Contents/Resources/root. Fejlesztéskor (`swift run`, csak DEBUG build): ./Resources/root.
    static var directory: URL? {
        let fm = FileManager.default
        if let url = Bundle.main.resourceURL?.appendingPathComponent("root"),
           fm.fileExists(atPath: url.appendingPathComponent("mvpn").path) {
            return url
        }
        #if DEBUG
        let dev = URL(fileURLWithPath: fm.currentDirectoryPath).appendingPathComponent("Resources/root")
        return fm.fileExists(atPath: dev.appendingPathComponent("mvpn").path) ? dev : nil
        #else
        return nil
        #endif
    }
}
