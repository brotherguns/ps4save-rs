// swift-tools-version: 6.0

import PackageDescription

let xapp = "/run/media/brotherguns/BROTHERGUNS/ps4save-ios/xtoolapp"

let package = Package(
    name: "PS4SaveTool",
    platforms: [
        .iOS(.v16),
    ],
    products: [
        // xtool convention: exactly one library product = the main app.
        .library(
            name: "PS4SaveTool",
            targets: ["PS4SaveApp"]
        ),
    ],
    targets: [
        .target(
            name: "PS4SaveApp",
            resources: [
                .copy("config.ini"),
            ],
            linkerSettings: [
                .unsafeFlags([
                    // hand-built objC UI + rust core, staged by build.sh
                    "\(xapp)/Libs/App.o",
                    "\(xapp)/Libs/libps4save_ios_core.a",
                    "-framework", "UIKit",
                    "-framework", "Foundation",
                    "-framework", "CoreGraphics",
                    "-framework", "UniformTypeIdentifiers",
                    "-lobjc",
                ])
            ]
        ),
    ]
)
