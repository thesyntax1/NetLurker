package dev.netlurker.android.ui

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.runtime.staticCompositionLocalOf

/**
 * Runtime string resolution.
 *
 * Keys are resolved by name rather than through generated R constants because the catalog
 * is shared with the desktop build: one CSV holds every key for all eight languages, a
 * generator emits the Android resources, and CI fails the build when a key used in code is
 * missing from any locale. `res/raw/keep.xml` keeps the shrinker from dropping strings that
 * are only reachable by name.
 *
 * Placeholders are written `{name}` and substituted by [invoke]; this keeps a translation
 * free to reorder the sentence, which positional specifiers would break.
 */
class Strings(private val context: Context) {

    private val cache = HashMap<String, Int>()

    operator fun invoke(key: String, vararg args: Pair<String, String>): String {
        var text = raw(key) ?: return key
        for ((name, value) in args) text = text.replace("{$name}", value)
        return text
    }

    /** Returns null when the key is absent, so callers can distinguish "untranslated". */
    fun raw(key: String): String? {
        val id = cache.getOrPut(key) {
            context.resources.getIdentifier(key, "string", context.packageName)
        }
        if (id == 0) return null
        return runCatching { context.getString(id) }.getOrNull()
    }

    fun has(key: String): Boolean = raw(key) != null

    /** A label resolver for the non-UI layers (exports, prompts, risk reasons). */
    fun resolver(): (String) -> String = { key -> invoke(key) }
}

val LocalStrings = staticCompositionLocalOf<Strings?> { null }

/** Convenience for composables: fails loudly in debug if used outside the provider. */
@Composable
fun strings(): Strings = checkNotNull(LocalStrings.current) {
    "LocalStrings is not provided; wrap the tree in NetLurkerTheme"
}
