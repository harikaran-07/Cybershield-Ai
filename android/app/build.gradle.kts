import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
}

android {
    namespace = "com.cybershieldai"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.cybershieldai"
        minSdk = 26
        targetSdk = 34
        versionCode = 3
        versionName = "2.2.0"

        // No cloud backend is compiled in: all detection runs on-device.
        // Users may point the app at a server THEY run (e.g. a PC with a
        // local Ollama model) via Settings → Backend Server.

        // Optional URL reputation key (§9): supplied via local.properties
        // (SB_API_KEY=...) — NEVER hardcoded in source. Empty = reputation
        // layer reports unavailable and local analysis is used.
        val localProps = Properties().apply {
            val f = rootProject.file("local.properties")
            if (f.exists()) f.inputStream().use { load(it) }
        }
        buildConfigField("String", "SB_API_KEY",
            "\"${localProps.getProperty("SB_API_KEY") ?: ""}\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }

    buildTypes {
        getByName("debug") { /* inherits defaultConfig BuildConfig */ }
    }
    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.retrofit)
    implementation(libs.retrofit.gson)
    implementation(libs.okhttp)
    implementation(libs.okhttp.logging)
    implementation(libs.coroutines.android)
    implementation(libs.datastore.preferences)
    implementation(libs.camera.core)
    implementation(libs.camera.camera2)
    implementation(libs.camera.lifecycle)
    implementation(libs.camera.view)
    implementation(libs.mlkit.barcode.scanning)
    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    ksp(libs.room.compiler)
    implementation(libs.work.runtime)

    // On-device LLM inference (spec §2): Google AI Edge / MediaPipe LLM
    // Inference task API — runs the installed .task model fully on-device.
    // No cloud, no API key, no native build required.
    implementation("com.google.mediapipe:tasks-genai:0.10.35")

    testImplementation(libs.junit)
    debugImplementation(libs.androidx.compose.ui.tooling)
}
