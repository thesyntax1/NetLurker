// NetLurker for Android — root build script.
// Versions are pinned on purpose: a reproducible APK must come out of CI byte-for-byte
// equivalent, and floating versions are how a green build turns red a month later.
plugins {
    id("com.android.application") version "8.7.0" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}
