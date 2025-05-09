// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "LibNotSignal",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "LibNotSignal",
            targets: ["LibNotSignal"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.0.0"),
    ],
    targets: [
        .target(
            name: "LibNotSignal",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ]),
        .executableTarget(
            name: "TestLibNotSignal",
            dependencies: ["LibNotSignal"]),
        .testTarget(
            name: "LibNotSignalTests",
            dependencies: ["LibNotSignal"]),
    ]
) 