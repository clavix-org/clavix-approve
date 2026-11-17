// swift-tools-version:6.0
// The protocol of clavix-approve, signer side, in Swift: the same work as
// web/lib, for the native app. No dependency beyond Apple's frameworks.
import PackageDescription

let package = Package(
    name: "ClavixCore",
    platforms: [.iOS(.v18), .macOS(.v14)],
    products: [
        .library(name: "ClavixCore", targets: ["ClavixCore"]),
    ],
    targets: [
        .target(name: "ClavixCore"),
        .testTarget(
            name: "ClavixCoreTests",
            dependencies: ["ClavixCore"]
        ),
    ]
)
