plugins {
    id("com.android.library")
    id("com.android.base")
    kotlin("android")
}

private fun findBuildToolsVersion(): String {
    val defaultBuildToolsVersion = "35.0.0"
    return File(System.getenv("ANDROID_HOME"), "build-tools").listFiles()?.filter { it.isDirectory }?.maxOfOrNull { it.name }
        ?.also { println("Using build tools version $it") }
        ?: defaultBuildToolsVersion
}

android {
    compileSdk = 34
    namespace = "io.github.libxposed.service"
    sourceSets {
        val main by getting
        main.apply {
            manifest.srcFile("service/service/src/main/AndroidManifest.xml")
            java.setSrcDirs(listOf("service/service/src/main/java"))
            aidl.setSrcDirs(listOf("service/interface/src/main/aidl"))
        }
    }

    defaultConfig {
        minSdk = 24
        //noinspection OldTargetApi
        targetSdk = 34
        buildToolsVersion = findBuildToolsVersion()
    }
    // Java 17 is required by libxposed-service
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = false
        resValues = false
        aidl = true
    }

    dependencies {
        compileOnly(libs.androidx.annotation)
    }

}

// I don't know why but this is required to make the AGP use JDK 17 to compile the source code.
// On my machine, even if I set the sourceCompatibility and targetCompatibility to JavaVersion.VERSION_17,
// and run Gradle with JDK 17, the AGP still uses JDK 11 to compile the source code.
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

// [WeKit-Mod] AIDL 生成文件修复：Windows 路径中的反斜杠会被 javac 误认为 Unicode 转义
// 在 AIDL 生成后、Java 编译前，将注释中的 \ 替换为 /
tasks.configureEach {
    if (name.contains("aidl", ignoreCase = true) && name.contains("Release", ignoreCase = true)) {
        doLast {
            val aidlOutputDir = file("${layout.buildDirectory.get()}/generated/aidl_source_output_dir/release/out")
            if (aidlOutputDir.exists()) {
                aidlOutputDir.walkTopDown().filter { it.extension == "java" }.forEach { javaFile ->
                    val content = javaFile.readText()
                    if (content.contains("\\\\") || content.contains("\\u") || content.contains("\\U")) {
                        val fixed = content.lines().joinToString("\n") { line ->
                            if (line.trimStart().startsWith("*") || line.trimStart().startsWith("//") || line.trimStart().startsWith("/*")) {
                                line.replace("\\", "/")
                            } else {
                                line
                            }
                        }
                        javaFile.writeText(fixed)
                        println("[WeKit-Mod] Sanitized AIDL output: ${javaFile.name}")
                    }
                }
            }
        }
    }
}
