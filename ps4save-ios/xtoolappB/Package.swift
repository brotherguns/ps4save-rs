// swift-tools-version: 6.0

import PackageDescription

let xapp = "/run/media/brotherguns/BROTHERGUNS/ps4save-ios/xtoolappB"

let package = Package(
    name: "PS4SaveToolB",
    platforms: [
        .iOS(.v16),
    ],
    products: [
        // xtool convention: exactly one library product = the main app.
        .library(
            name: "PS4SaveToolB",
            targets: ["PS4SaveAppB"]
        ),
    ],
    targets: [
        .target(
            name: "PS4SaveAppB",
            resources: [
                .copy("config.ini"),
            ],
            linkerSettings: [
                .unsafeFlags([
                    // hand-built objC UI + rust core, staged by build.sh
                    // (reuses the Libs staged for the main app)
                    "/run/media/brotherguns/BROTHERGUNS/ps4save-ios/xtoolapp/Libs/App.o",
                    "/run/media/brotherguns/BROTHERGUNS/ps4save-ios/xtoolapp/Libs/libps4save_ios_core.a",
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
