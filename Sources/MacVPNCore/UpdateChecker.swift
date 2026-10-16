import Foundation

// MARK: - HTTP

public struct HTTPResponse: Sendable {
    public var status: Int
    public var data: Data

    public init(status: Int, data: Data) {
        self.status = status
        self.data = data
    }
}

/// A hálózati réteg (tesztben mockolható). Csak HTTPS-t és a megengedett hostokat használja.
public protocol HTTPClient: Sendable {
    func get(_ url: URL) async throws -> HTTPResponse
    /// Letöltés egy ideiglenes fájlba; a fájl a hívóé (át kell helyeznie vagy törölnie).
    func download(_ url: URL) async throws -> (file: URL, status: Int)
}

/// `URLSession` alapú kliens. Átirányítást csak HTTPS-re és a GitHub letöltési hostjaira enged.
public final class URLSessionHTTPClient: NSObject, HTTPClient, URLSessionTaskDelegate, @unchecked Sendable {
    private let session: URLSession

    public override init() {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 600
        config.httpAdditionalHeaders = ["User-Agent": "MacVPN-Updater"]
        session = URLSession(configuration: config)
        super.init()
    }

    public func get(_ url: URL) async throws -> HTTPResponse {
        guard UpdateURLPolicy.isAllowedRedirect(url) else { throw UpdateError.untrustedURL(url.absoluteString) }
        var request = URLRequest(url: url)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        let (data, response) = try await session.data(for: request, delegate: self)
        return HTTPResponse(status: (response as? HTTPURLResponse)?.statusCode ?? 0, data: data)
    }

    public func download(_ url: URL) async throws -> (file: URL, status: Int) {
        guard UpdateURLPolicy.isAllowedDownload(url) else { throw UpdateError.untrustedURL(url.absoluteString) }
        let (file, response) = try await session.download(for: URLRequest(url: url), delegate: self)
        return (file, (response as? HTTPURLResponse)?.statusCode ?? 0)
    }

    public func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                           newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        if let url = request.url, UpdateURLPolicy.isAllowedRedirect(url) {
            completionHandler(request)
        } else {
            completionHandler(nil)  // nem követjük: a 3xx válasz hibaként jut vissza
        }
    }
}

/// Mely URL-ekről tölthet az updater.
public enum UpdateURLPolicy {
    /// A release asset `browser_download_url`-je csak ezekre mutathat.
    public static let downloadHosts: Set<String> = ["github.com", "objects.githubusercontent.com"]
    /// Átirányítás (és az API) célja. A GitHub az assetet ma már a `release-assets` hostról szolgálja ki;
    /// a tartalom hitelességét a SHA-256 adja, a host-lista csak mélységi védelem.
    public static let redirectHosts: Set<String> = downloadHosts
        .union(["api.github.com", "release-assets.githubusercontent.com"])

    public static func isAllowedDownload(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "https" && downloadHosts.contains(url.host?.lowercased() ?? "")
            && url.user == nil && url.password == nil && (url.port == nil || url.port == 443)
    }

    public static func isAllowedRedirect(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "https" && redirectHosts.contains(url.host?.lowercased() ?? "")
            && url.user == nil && url.password == nil && (url.port == nil || url.port == 443)
    }
}

// MARK: - Modell

public enum UpdateError: LocalizedError, Equatable {
    case invalidRepo(String)
    case http(Int)
    case invalidResponse
    case missingAsset(String)
    case untrustedURL(String)
    case invalidChecksumFile
    case checksumMismatch
    case mountFailed(String)
    case invalidApp(String)
    case notWritable(String)
    case helperFailed(String)

    public var errorDescription: String? {
        switch self {
        case .invalidRepo(let r): return L10n.tr("Invalid update source: %@", r)
        case .http(404): return L10n.tr("No release available (HTTP 404)")
        case .http(403): return L10n.tr("GitHub is temporarily limiting requests (HTTP 403). Try again later.")
        case .http(let code): return L10n.tr("The server returned an error (HTTP %ld)", code)
        case .invalidResponse: return L10n.tr("Unexpected response from GitHub")
        case .missingAsset(let name): return L10n.tr("Missing from the release: %@", name)
        case .untrustedURL(let url): return L10n.tr("Download address not allowed: %@", url)
        case .invalidChecksumFile: return L10n.tr("Invalid checksum file (.sha256)")
        case .checksumMismatch: return L10n.tr("The checksum (SHA-256) of the downloaded file does not match. Update cancelled.")
        case .mountFailed(let msg): return L10n.tr("Cannot mount the disk image: %@", msg)
        case .invalidApp(let msg): return L10n.tr("The app on the disk image is not accepted: %@", msg)
        case .notWritable(let path):
            return L10n.tr("The app's location is not writable: %@. Drag the app to the Applications folder, or update manually from the DMG.", path)
        case .helperFailed(let msg): return L10n.tr("Cannot start the installer helper script: %@", msg)
        }
    }
}

/// `X.Y.Z` verzió. A `v` előtag és a pre-release / build rész (`-beta.1`, `+abc`) figyelmen kívül marad.
public struct SemVer: Comparable, Equatable, CustomStringConvertible, Sendable {
    public let major: Int, minor: Int, patch: Int

    public init(major: Int, minor: Int, patch: Int) {
        self.major = major
        self.minor = minor
        self.patch = patch
    }

    public init?(_ string: String) {
        var s = string.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("v") || s.hasPrefix("V") { s.removeFirst() }
        if let cut = s.firstIndex(where: { $0 == "-" || $0 == "+" }) { s = String(s[..<cut]) }
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...3).contains(parts.count) else { return nil }
        var numbers: [Int] = []
        for p in parts {
            guard !p.isEmpty, p.allSatisfy(\.isASCII), p.allSatisfy(\.isNumber), let n = Int(p) else { return nil }
            numbers.append(n)
        }
        while numbers.count < 3 { numbers.append(0) }
        self.init(major: numbers[0], minor: numbers[1], patch: numbers[2])
    }

    public static func < (a: SemVer, b: SemVer) -> Bool {
        (a.major, a.minor, a.patch) < (b.major, b.minor, b.patch)
    }

    public var description: String { "\(major).\(minor).\(patch)" }
}

public struct ReleaseAsset: Equatable, Sendable {
    public let name: String
    public let url: URL
}

public struct Release: Equatable, Sendable {
    /// Pl. `v0.2.0`.
    public let tag: String
    /// A tag `v` nélkül; ennek kell egyeznie a csatolt app `CFBundleShortVersionString`-jével.
    public let version: String
    public let notes: String
    public let pageURL: URL?
    public let dmg: ReleaseAsset
    public let checksum: ReleaseAsset

    public func isNewer(than current: String) -> Bool {
        guard let mine = SemVer(current), let theirs = SemVer(version) else { return false }
        return theirs > mine
    }
}

// MARK: - Ellenőrzés

public struct UpdateChecker: Sendable {
    public static let infoPlistKey = "MacVPNUpdateRepo"
    public let repo: String
    let http: HTTPClient

    /// `owner/repo` formátum, más karakter nélkül.
    public static func isValidRepo(_ repo: String) -> Bool {
        repo.range(of: "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$", options: .regularExpression) != nil
            && !repo.hasSuffix("/.") && !repo.hasSuffix("/..")
    }

    /// Az `Info.plist` `MacVPNUpdateRepo` kulcsa; nil, ha hiányzik vagy érvénytelen (ilyenkor nincs frissítés-ellenőrzés).
    public static func repo(fromInfo info: [String: Any]?) -> String? {
        guard let value = info?[infoPlistKey] as? String else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        return isValidRepo(trimmed) ? trimmed : nil
    }

    public init(repo: String, http: HTTPClient) throws {
        guard Self.isValidRepo(repo) else { throw UpdateError.invalidRepo(repo) }
        self.repo = repo
        self.http = http
    }

    public var latestReleaseURL: URL { URL(string: "https://api.github.com/repos/\(repo)/releases/latest")! }

    public func latestRelease() async throws -> Release {
        let response = try await http.get(latestReleaseURL)
        guard response.status == 200 else { throw UpdateError.http(response.status) }
        return try Self.parseRelease(response.data)
    }

    private struct RawRelease: Decodable {
        struct Asset: Decodable {
            let name: String
            let browser_download_url: String
        }
        let tag_name: String
        let body: String?
        let html_url: String?
        let draft: Bool?
        let prerelease: Bool?
        let assets: [Asset]
    }

    /// A GitHub `releases/latest` JSON-ja. A DMG neve `MacVPN-<verzió>.dmg`, mellette `MacVPN-<verzió>.dmg.sha256`.
    public static func parseRelease(_ data: Data) throws -> Release {
        guard let raw = try? JSONDecoder().decode(RawRelease.self, from: data) else { throw UpdateError.invalidResponse }
        guard raw.draft != true, raw.prerelease != true, SemVer(raw.tag_name) != nil,
              raw.tag_name.range(of: "^v?[0-9]+(\\.[0-9]+){0,2}$", options: .regularExpression) != nil else {
            throw UpdateError.invalidResponse
        }
        let version = raw.tag_name.hasPrefix("v") ? String(raw.tag_name.dropFirst()) : raw.tag_name
        let dmgName = "MacVPN-\(version).dmg"
        func asset(_ name: String) throws -> ReleaseAsset {
            guard let a = raw.assets.first(where: { $0.name == name }) else { throw UpdateError.missingAsset(name) }
            guard let url = URL(string: a.browser_download_url), UpdateURLPolicy.isAllowedDownload(url) else {
                throw UpdateError.untrustedURL(a.browser_download_url)
            }
            return ReleaseAsset(name: a.name, url: url)
        }
        let page = raw.html_url.flatMap(URL.init(string:)).flatMap { UpdateURLPolicy.isAllowedDownload($0) ? $0 : nil }
        return Release(tag: raw.tag_name, version: version, notes: raw.body ?? "", pageURL: page,
                       dmg: try asset(dmgName), checksum: try asset(dmgName + ".sha256"))
    }
}

// MARK: - Súgó

public enum UserGuide {
    public static let fallbackRepo = "SepsiG/MacVPN"

    /// Ugyanaz a választás, mint az app felületéé: az első magyar vagy angol preferált nyelv, egyébként `en`.
    public static func language(preferred: [String]) -> String {
        AppLanguage.resolve(preferred: preferred).rawValue
    }

    public static func url(repo: String?, preferredLanguages: [String]) -> URL {
        let r = repo.flatMap { UpdateChecker.isValidRepo($0) ? $0 : nil } ?? fallbackRepo
        let lang = language(preferred: preferredLanguages)
        return URL(string: "https://github.com/\(r)/blob/main/docs/user-guide.\(lang).md")!
    }
}
