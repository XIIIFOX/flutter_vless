// swift-tools-version: 5.9

import PackageDescription
import Foundation

let xrayReleaseTag = "xray-ios-v26.7.28"
let xrayChecksum = "2c0ddf1f9f93b275a7b2b9320ca868b37665d08e5369663a27e3d853d015f1bc"
let packageDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let xrayPackageLocalPath = "XRay.xcframework"
let xrayRepoLocalPath = "../XRay.xcframework"
let xrayPackageLocalAbsolutePath = packageDirectory.appendingPathComponent(xrayPackageLocalPath).path
let xrayRepoLocalAbsolutePath = packageDirectory.appendingPathComponent(xrayRepoLocalPath).standardized.path
let xrayEnv = ProcessInfo.processInfo.environment
let xrayBinaryURL = xrayEnv["FLUTTER_VLESS_XRAY_URL"] ?? "https://github.com/XIIIFOX/flutter_vless/releases/download/\(xrayReleaseTag)/XRay.xcframework.zip"
let xrayBinaryChecksum = xrayEnv["FLUTTER_VLESS_XRAY_CHECKSUM"] ?? xrayChecksum
let xrayBinaryTarget: Target

if FileManager.default.fileExists(atPath: xrayPackageLocalAbsolutePath) {
    xrayBinaryTarget = .binaryTarget(name: "XRay", path: xrayPackageLocalPath)
} else if FileManager.default.fileExists(atPath: xrayRepoLocalAbsolutePath) {
    xrayBinaryTarget = .binaryTarget(name: "XRay", path: xrayRepoLocalPath)
} else {
    xrayBinaryTarget = .binaryTarget(name: "XRay", url: xrayBinaryURL, checksum: xrayBinaryChecksum)
}

let package = Package(
    name: "flutter_vless",
    platforms: [
        .iOS("15.0")
    ],
    products: [
        .library(name: "flutter-vless", targets: ["flutter_vless"]),
        .library(name: "flutter-vless-tunnel-support", targets: ["flutter_vless_tunnel_support"])
    ],
    dependencies: [
        .package(name: "FlutterFramework", path: "../FlutterFramework"),
        .package(url: "https://github.com/EbrahimTahernejad/Tun2SocksKit", exact: "5.15.0")
    ],
    targets: [
        .target(
            name: "flutter_vless",
            dependencies: [
                .product(name: "FlutterFramework", package: "FlutterFramework"),
                "XRay"
            ],
            linkerSettings: [
                .linkedLibrary("resolv")
            ]
        ),
        .target(
            name: "flutter_vless_tunnel_support",
            dependencies: [
                "XRay",
                .product(name: "Tun2SocksKit", package: "Tun2SocksKit"),
                .product(name: "Tun2SocksKitC", package: "Tun2SocksKit")
            ],
            linkerSettings: [
                .linkedLibrary("resolv")
            ]
        ),
        xrayBinaryTarget,
        .testTarget(
            name: "flutter_vless_tunnel_supportTests",
            dependencies: ["flutter_vless_tunnel_support"]
        )
    ]
)
