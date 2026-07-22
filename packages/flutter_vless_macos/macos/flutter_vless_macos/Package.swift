// swift-tools-version: 5.9

import PackageDescription
import Foundation

let xrayReleaseTag = "xray-macos-v26.7.11"
let xrayChecksum = "4cb8f9aa86e34d8432c50bb1abdafde25ed8185f545bd4d43d98400aa79d43c2"
let packageDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let xrayPackageLocalPath = "XRay.xcframework"
let xrayRepoLocalPath = "../XRay.xcframework"
let xrayPackageLocalAbsolutePath = packageDirectory.appendingPathComponent(xrayPackageLocalPath).path
let xrayRepoLocalAbsolutePath = packageDirectory.appendingPathComponent(xrayRepoLocalPath).standardized.path
let xrayEnv = ProcessInfo.processInfo.environment
let xrayBinaryURL = xrayEnv["FLUTTER_VLESS_MACOS_FRAMEWORK_URL"] ?? "https://github.com/XIIIFOX/flutter_vless/releases/download/\(xrayReleaseTag)/XRay.xcframework.zip"
let xrayBinaryChecksum = xrayEnv["FLUTTER_VLESS_MACOS_FRAMEWORK_SHA256"] ?? xrayChecksum
let xrayBinaryTarget: Target

if FileManager.default.fileExists(atPath: xrayPackageLocalAbsolutePath) {
    xrayBinaryTarget = .binaryTarget(name: "XRay", path: xrayPackageLocalPath)
} else if FileManager.default.fileExists(atPath: xrayRepoLocalAbsolutePath) {
    xrayBinaryTarget = .binaryTarget(name: "XRay", path: xrayRepoLocalPath)
} else {
    xrayBinaryTarget = .binaryTarget(name: "XRay", url: xrayBinaryURL, checksum: xrayBinaryChecksum)
}

let package = Package(
    name: "flutter_vless_macos",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "flutter-vless-macos", targets: ["flutter_vless_macos"]),
        .library(name: "flutter-vless-macos-tunnel-support", targets: ["flutter_vless_macos_tunnel_support"])
    ],
    dependencies: [
        .package(url: "https://github.com/EbrahimTahernejad/Tun2SocksKit", exact: "5.15.0")
    ],
    targets: [
        .target(
            name: "flutter_vless_macos",
            dependencies: [
                "XRay",
                "CXRay"
            ],
            linkerSettings: [
                .linkedLibrary("resolv")
            ]
        ),
        .target(
            name: "flutter_vless_macos_tunnel_support",
            dependencies: [
                "XRay",
                "CXRay",
                .product(name: "Tun2SocksKit", package: "Tun2SocksKit"),
                .product(name: "Tun2SocksKitC", package: "Tun2SocksKit")
            ],
            linkerSettings: [
                .linkedLibrary("resolv")
            ]
        ),
        .target(
            name: "CXRay",
            dependencies: ["XRay"],
            publicHeadersPath: "include"
        ),
        .testTarget(
            name: "flutter_vless_macos_tunnel_supportTests",
            dependencies: ["flutter_vless_macos_tunnel_support"]
        ),
        xrayBinaryTarget
    ]
)
