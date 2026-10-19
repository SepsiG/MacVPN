/// A kilépési kérés (Cmd+Q, Dock, kijelentkezés) kezelése: kell-e kérdezni, vagy azonnal kiléphet az app.
public enum QuitPolicy {
    public enum Decision: Equatable {
        /// Nincs mit kérdezni, vagy a kilépést már megerősítették (menü Kilépés, frissítés).
        case terminateNow
        /// A kilépési kérdések (nem mentett változások, aktív kapcsolatok) futnak, a válasz aszinkron.
        case ask
    }

    public static func decide(alreadyConfirmed: Bool, hasUnsavedChanges: Bool, hasActiveConnections: Bool) -> Decision {
        if alreadyConfirmed { return .terminateNow }
        return (hasUnsavedChanges || hasActiveConnections) ? .ask : .terminateNow
    }
}
