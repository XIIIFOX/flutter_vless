pluginManagement {
    val flutterSdkPath =
        run {
            val properties = java.util.Properties()
            file("local.properties").inputStream().use { properties.load(it) }
            val flutterSdkPath = properties.getProperty("flutter.sdk")
            require(flutterSdkPath != null) { "flutter.sdk not set in local.properties" }
            flutterSdkPath
        }

    includeBuild("$flutterSdkPath/packages/flutter_tools/gradle")

    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    id("dev.flutter.flutter-plugin-loader") version "1.0.0"
    id("com.android.application") version "8.11.1" apply false
    id("org.jetbrains.kotlin.android") version "2.2.20" apply false
}

include(":app")

// Explicit production verification must never resolve a development override.
if (providers.gradleProperty("flutterVlessOfficialRuntimeVerification").orNull == "true") {
    check(providers.gradleProperty("flutterVlessAndroidRuntimeRepo").orNull.isNullOrBlank() &&
        providers.environmentVariable("FLUTTER_VLESS_ANDROID_RUNTIME_REPO").orNull.isNullOrBlank()) {
        "Official runtime verification rejects repository overrides"
    }
    val version = providers.gradleProperty("flutterVlessXrayRuntimeVersion").orNull
    check(version == null || version == "26.7.28-protect1") {
        "Official runtime verification rejects version overrides"
    }
    check(gradle.startParameter.dependencyVerificationMode == org.gradle.api.artifacts.verification.DependencyVerificationMode.STRICT) {
        "Official runtime verification requires strict dependency verification"
    }
}
