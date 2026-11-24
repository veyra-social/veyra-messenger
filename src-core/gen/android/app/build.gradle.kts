import java.io.File
import java.util.Properties
import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.internal.os.OperatingSystem

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

val signingProperties = Properties().apply {
    val propFile = file("key.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

fun signingValue(propertyName: String, envName: String): String? =
    signingProperties.getProperty(propertyName)?.takeIf { it.isNotBlank() }
        ?: System.getenv(envName)?.takeIf { it.isNotBlank() }

val releaseStoreFile = signingValue("storeFile", "VEYRA_ANDROID_STORE_FILE")
val releaseStorePassword = signingValue("storePassword", "VEYRA_ANDROID_STORE_PASSWORD")
val releaseKeyAlias = signingValue("keyAlias", "VEYRA_ANDROID_KEY_ALIAS")
val releaseKeyPassword = signingValue("keyPassword", "VEYRA_ANDROID_KEY_PASSWORD")
val hasReleaseSigning = listOf(
    releaseStoreFile,
    releaseStorePassword,
    releaseKeyAlias,
    releaseKeyPassword,
).all { !it.isNullOrBlank() }

android {
    compileSdk = 36
    namespace = "app.veyra.messenger"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        // networkSecurityConfig overrides usesCleartextTraffic when present:
        // release blocks cleartext except loopback (in-process media server),
        // debug stays fully permissive for the LAN dev server.
        manifestPlaceholders["networkSecurityConfig"] = "@xml/network_security_config"
        applicationId = "app.veyra.messenger"
        minSdk = 24
        targetSdk = 36
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
    }
    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(releaseStoreFile!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            manifestPlaceholders["networkSecurityConfig"] = "@xml/network_security_config_debug"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            // Sign debug APKs with the project release certificate when it is configured.
            // Debug installs as app.veyra.messenger.debug, so it can live next to the
            // release app while still using the project signing identity when available.
            // Without `key.properties` / env vars present, AGP falls back to its default
            // debug-only signing key.
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
            // Intentionally NOT adding any patterns to `jniLibs.keepDebugSymbols`. AGP 8 on
            // debug variants does not run native-lib strip automatically, so we run our own
            // `llvm-strip --strip-unneeded` step after every `rustBuild*Debug` task (see the
            // `stripDebugJniLibs` block below). That step removes `.symtab + .strtab` while
            // leaving `.dynsym` / `.eh_frame` / `.rodata` (tracing literals) untouched.
        }
        getByName("release") {
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
            isMinifyEnabled = true
            proguardFiles(
                *fileTree(".") { include("**/*.pro") }
                    .plus(getDefaultProguardFile("proguard-android-optimize.txt"))
                    .toList().toTypedArray()
            )
        }
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        buildConfig = true
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("-Xlint:-options")
}

rust {
    rootDirRel = "../../../"
}

// Strip `.symtab + .strtab` from Rust-built `libveyra_messenger_lib.so` for every
// debug ABI before AGP merges/packages the native libs into the APK.
//
// Why a dedicated task instead of a `doLast` on `rustBuild<Arch>Debug`:
//   `tauri android build` runs `cargo ndk` directly *before* Gradle even starts,
//   so by the time Gradle evaluates `:app:rustBuild<Arch>Debug` the produced .so
//   is already there and the task is reported UP-TO-DATE — any `doLast` we attach
//   is skipped. A separate task with `outputs.upToDateWhen { false }` always runs
//   and we wire `merge<Arch>DebugNativeLibs` to depend on it so the merge picks up
//   the stripped file.
//
// `--strip-unneeded` removes only symbols not required for dynamic linking
// (`.symtab` + `.strtab`). It keeps `.dynsym`, `.dynstr`, `.eh_frame`,
// `.eh_frame_hdr`, `.gcc_except_table`, `.rodata` and everything else loaded at
// runtime, so app functionality, `tracing` output (which uses `module_path!`/
// `file!` literals living in `.rodata`), and panic unwinding all stay intact.
// Panic backtraces show raw addresses instead of symbol names — same diagnostic
// tradeoff that `[profile.dev] strip = "debuginfo"` in `src-tauri/Cargo.toml`
// already accepts.
val veyraStripHostTag: String = when {
    OperatingSystem.current().isWindows -> "windows-x86_64"
    OperatingSystem.current().isMacOsX -> "darwin-x86_64"
    else -> "linux-x86_64"
}
val veyraStripExeName: String =
    if (OperatingSystem.current().isWindows) "llvm-strip.exe" else "llvm-strip"

fun veyraResolveStripTool(): File? {
    fun newestNdkInSdk(sdkRoot: String?): String? {
        if (sdkRoot.isNullOrBlank()) return null
        val ndkRoot = File(sdkRoot, "ndk")
        if (!ndkRoot.isDirectory) return null
        return ndkRoot.listFiles()
            ?.filter { it.isDirectory }
            ?.maxByOrNull { it.name }
            ?.absolutePath
    }
    val candidates = listOfNotNull(
        System.getenv("NDK_HOME"),
        System.getenv("ANDROID_NDK_HOME"),
        System.getenv("ANDROID_NDK_ROOT"),
        newestNdkInSdk(System.getenv("ANDROID_HOME")),
        newestNdkInSdk(System.getenv("ANDROID_SDK_ROOT")),
    )
    for (ndk in candidates) {
        val tool = File(ndk, "toolchains/llvm/prebuilt/$veyraStripHostTag/bin/$veyraStripExeName")
        if (tool.exists()) return tool
    }
    return null
}

val veyraArchToTriple: Map<String, String> = mapOf(
    "Arm64" to "aarch64-linux-android",
    "Arm" to "armv7-linux-androideabi",
    "X86" to "i686-linux-android",
    "X86_64" to "x86_64-linux-android",
)

for ((arch, triple) in veyraArchToTriple) {
    val stripTaskName = "veyraStripJniLibs${arch}Debug"
    val rustTaskName = "rustBuild${arch}Debug"
    val mergeTaskName = "merge${arch}DebugNativeLibs"
    val stripTask = tasks.register(stripTaskName) {
        group = "veyra"
        description = "Strip .symtab + .strtab from libveyra_messenger_lib.so ($arch debug)"
        outputs.upToDateWhen { false }
        mustRunAfter(rustTaskName)
        doLast {
            val stripTool = veyraResolveStripTool() ?: run {
                logger.warn("[veyra-strip] llvm-strip not found via NDK env vars; APK keeps full symbol table")
                return@doLast
            }
            val so = file("../../../target/$triple/debug/libveyra_messenger_lib.so")
            if (!so.exists()) {
                logger.warn("[veyra-strip] $so missing, skipping strip for $arch")
                return@doLast
            }
            val sizeBefore = so.length()
            exec {
                commandLine(stripTool.absolutePath, "--strip-unneeded", so.absolutePath)
            }
            val sizeAfter = so.length()
            logger.lifecycle(
                "[veyra-strip] $arch: ${sizeBefore / 1024 / 1024} MB -> ${sizeAfter / 1024 / 1024} MB"
            )
        }
    }

    afterEvaluate {
        // Both `merge<Arch>DebugJniLibFolders` and `merge<Arch>DebugNativeLibs` may copy
        // the .so into intermediate dirs; the JNI-folder merge runs *first* in AGP's
        // chain and is the one that materialises an unstripped snapshot if we strip too
        // late. Wire strip in front of both so the merge captures the post-strip file.
        val mergeTargets = listOf(
            "merge${arch}DebugJniLibFolders",
            "merge${arch}DebugNativeLibs",
        )
        for (target in mergeTargets) {
            tasks.matching { it.name == target }.configureEach {
                dependsOn(stripTask)
            }
        }
    }
}

dependencies {
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

apply(from = "tauri.build.gradle.kts")
