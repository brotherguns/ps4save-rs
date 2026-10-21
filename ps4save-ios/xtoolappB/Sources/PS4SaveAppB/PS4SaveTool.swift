import UIKit

@main
final class PS4SaveToolBEntry {
    static func main() {
        // App.m holds the whole UIKit UI (including the PSAppDelegate class);
        // this root only spins the application loop with that delegate.
        UIApplicationMain(
            CommandLine.argc,
            CommandLine.unsafeArgv,
            nil,
            "AppDelegate"
        )
    }
}
