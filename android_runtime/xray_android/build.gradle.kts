plugins {
    id("com.android.library") version "8.11.1"
    id("maven-publish")
    id("signing")
}

group = "dev.tfox.fluttervless"
version = providers.gradleProperty("xrayRuntimeVersion").orElse("26.7.28").get()

val runtimeSourceDir = layout.projectDirectory.dir("src/main")
val requiredRuntimeFiles = listOf(
    "jniLibs/arm64-v8a/libxray.so",
    "jniLibs/arm64-v8a/libtun2socks.so",
    "jniLibs/armeabi-v7a/libxray.so",
    "jniLibs/armeabi-v7a/libtun2socks.so",
    "jniLibs/x86/libxray.so",
    "jniLibs/x86/libtun2socks.so",
    "jniLibs/x86_64/libxray.so",
    "jniLibs/x86_64/libtun2socks.so",
    "assets/geoip.dat",
    "assets/geosite.dat",
)

tasks.register("verifyRuntimeInputs") {
    group = "verification"
    description = "Checks that the Android Xray runtime inputs exist before packaging the AAR."

    doLast {
        val missing = requiredRuntimeFiles
            .map { runtimeSourceDir.file(it).asFile }
            .filterNot { it.isFile }

        check(missing.isEmpty()) {
            "Missing Android Xray runtime inputs:\n" + missing.joinToString("\n") { it.absolutePath }
        }
    }
}

android {
    namespace = "dev.tfox.fluttervless.xray"
    compileSdk = 36

    defaultConfig {
        minSdk = 23
    }

    sourceSets {
        getByName("main") {
            manifest.srcFile("src/main/AndroidManifest.xml")
            jniLibs.srcDir(runtimeSourceDir.dir("jniLibs"))
            assets.srcDir(runtimeSourceDir.dir("assets"))
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                artifactId = "xray-android"

                pom {
                    name.set("flutter_vless Xray Android Runtime")
                    description.set("Android AAR with Xray-core runtime binaries and geodata for flutter_vless.")
                    url.set("https://github.com/XIIIFOX/flutter_vless")

                    licenses {
                        license {
                            name.set("MIT License")
                            url.set("https://opensource.org/license/mit")
                        }
                    }

                    developers {
                        developer {
                            id.set("xiiifox")
                            name.set("XIIIFOX")
                            url.set("https://github.com/XIIIFOX")
                        }
                    }

                    scm {
                        connection.set("scm:git:https://github.com/XIIIFOX/flutter_vless.git")
                        developerConnection.set("scm:git:ssh://git@github.com/XIIIFOX/flutter_vless.git")
                        url.set("https://github.com/XIIIFOX/flutter_vless")
                    }
                }
            }
        }

        repositories {
            maven {
                name = "localBuild"
                url = layout.buildDirectory.dir("repo").get().asFile.toURI()
            }
        }
    }

    val signingKey = providers.environmentVariable("SIGNING_IN_MEMORY_KEY").orNull
    val signingPassword = providers.environmentVariable("SIGNING_IN_MEMORY_KEY_PASSWORD").orNull
    val signingKeyId = providers.environmentVariable("SIGNING_IN_MEMORY_KEY_ID").orNull

    if (!signingKey.isNullOrBlank()) {
        signing {
            isRequired = true
            if (signingKeyId.isNullOrBlank()) {
                useInMemoryPgpKeys(signingKey, signingPassword)
            } else {
                useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
            }
            sign(publishing.publications["release"])
        }
    }
}
