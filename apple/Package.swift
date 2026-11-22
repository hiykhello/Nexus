// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NexusApple",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
    ],
    products: [
        .library(name: "NexusCoreBridge", targets: ["NexusCoreBridge"]),
        .library(name: "NexusSharedUI", targets: ["NexusSharedUI"]),
        .executable(name: "NexusMenuBarApp", targets: ["NexusMenuBarApp"]),
    ],
    targets: [
        .target(
            name: "NexusCoreBridge",
            path: "Sources/NexusCoreBridge"
        ),
        .target(
            name: "NexusSharedUI",
            dependencies: ["NexusCoreBridge"],
            path: "Sources/NexusSharedUI"
        ),
        .executableTarget(
            name: "NexusMenuBarApp",
            dependencies: ["NexusCoreBridge", "NexusSharedUI"],
            path: "Sources/NexusMenuBarApp"
        ),
        .testTarget(
            name: "NexusCoreBridgeTests",
            dependencies: ["NexusCoreBridge"],
            path: "Tests/NexusCoreBridgeTests"
        ),
    ]
)
