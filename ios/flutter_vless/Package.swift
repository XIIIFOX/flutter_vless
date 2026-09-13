// swift-tools-version: 5.9

import PackageDescription
import Foundation

let xrayReleaseTag = "xray-ios-v26.9.9"
let xrayChecksum = "dd07e1897bdff4c3e4e1a3958629ad5d9517676ecd470bfd99ec35e46184549e"
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
                "flutter_vless_privacy",
                "XRay"
            ],
            linkerSettings: [
                .linkedLibrary("resolv")
            ]
        ),
        .target(
            name: "flutter_vless_privacy",
            linkerSettings: [.linkedFramework("Security")]
        ),
        .target(
            name: "flutter_vless_tunnel_support",
            dependencies: [
                "flutter_vless_privacy",
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
