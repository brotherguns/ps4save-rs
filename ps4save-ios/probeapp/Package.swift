// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "DocPickerProbe",
    platforms: [
        .iOS(.v16),
    ],
    products: [
        // xtool convention: exactly one library product = the main app.
        .library(
            name: "DocPickerProbe",
            targets: ["DocPickerProbe"]
        ),
    ],
    targets: [
        .target(
            name: "DocPickerProbe",
            linkerSettings: [
                .unsafeFlags([
                    "-framework", "UIKit",
                    "-framework", "Foundation",
                    "-framework", "CoreGraphics",
                    "-framework", "UniformTypeIdentifiers",
                    "-lobjc",
                ])
            ]
        ),
    ],
    // Swift 5 mode: plain UIApplicationDelegate pattern without strict
    // concurrency friction.
    swiftLanguageVersions: [.v5]
)
