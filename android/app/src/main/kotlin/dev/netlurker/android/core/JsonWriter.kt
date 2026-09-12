package dev.netlurker.android.core

/**
 * Minimal deterministic JSON writer, in the spirit of the desktop build's src/json.cpp.
 *
 * Written by hand rather than pulling a library because the export format is part of the
 * product: key order must be stable so two exports of the same session diff cleanly, and
 * it keeps the unit tests runnable on a plain JVM.
 */
class JsonWriter(private val indent: String = "  ") {

    private val sb = StringBuilder()
    private val stack = ArrayDeque<Frame>()

    /** Set after [name]: the value that follows must be written with no separator. */
    private var afterName = false

    private class Frame {
        var empty = true
    }

    private fun newlineIndent(depth: Int) {
        if (indent.isEmpty()) return
        sb.append('\n')
        repeat(depth) { sb.append(indent) }
    }

    /** Separator + indentation before a value or a key. */
    private fun beforeValue() {
        val frame = stack.lastOrNull() ?: return
        if (frame.empty) {
            frame.empty = false
        } else {
            sb.append(',')
        }
        newlineIndent(stack.size)
    }

    private fun open(array: Boolean) {
        if (afterName) {
            afterName = false
        } else {
            beforeValue()
        }
        sb.append(if (array) '[' else '{')
        stack.addLast(Frame())
    }

    private fun close(c: Char) {
        val frame = stack.removeLastOrNull() ?: return
        if (!frame.empty) newlineIndent(stack.size)
        sb.append(c)
    }

    fun beginObject(): JsonWriter = also { open(false) }

    fun endObject(): JsonWriter = also { close('}') }

    fun beginArray(): JsonWriter = also { open(true) }

    fun endArray(): JsonWriter = also { close(']') }

    fun name(key: String): JsonWriter {
        check(stack.isNotEmpty()) { "name() at the top level" }
        beforeValue()
        escape(sb, key)
        sb.append(':')
        if (indent.isNotEmpty()) sb.append(' ')
        afterName = true
        return this
    }

    private fun raw(text: String) {
        if (afterName) {
            afterName = false
        } else {
            beforeValue()
        }
        sb.append(text)
    }

    /** Emits `"k": null` rather than dropping the key, so a consumer can tell that a
     *  field was looked for and found absent from the field never having existed. */
    fun value(v: String?): JsonWriter {
        if (v == null) {
            raw("null")
        } else {
            val out = StringBuilder()
            escape(out, v)
            raw(out.toString())
        }
        return this
    }

    fun value(v: Boolean): JsonWriter = also { raw(if (v) "true" else "false") }

    fun value(v: Long): JsonWriter = also { raw(v.toString()) }

    fun value(v: Int): JsonWriter = also { raw(v.toLong().toString()) }

    fun value(v: Double): JsonWriter = also {
        raw(if (v.isNaN() || v.isInfinite()) "null"
        else String.format(java.util.Locale.ROOT, "%.2f", v))
    }

    fun value(v: Int?): JsonWriter = if (v == null) also { raw("null") } else value(v.toInt())

    fun value(v: Long?): JsonWriter = if (v == null) also { raw("null") } else value(v.toLong())

    fun build(): String {
        check(stack.isEmpty()) { "unbalanced JSON: ${stack.size} container(s) still open" }
        return sb.toString()
    }

    override fun toString(): String = build()

    companion object {
        fun escape(out: StringBuilder, s: String) {
            out.append('"')
            for (ch in s) {
                when (ch) {
                    '"' -> out.append("\\\"")
                    '\\' -> out.append("\\\\")
                    '\n' -> out.append("\\n")
                    '\r' -> out.append("\\r")
                    '\t' -> out.append("\\t")
                    '\b' -> out.append("\\b")
                    '\u000C' -> out.append("\\f")
                    else -> if (ch.code < 0x20) {
                        out.append(String.format(java.util.Locale.ROOT, "\\u%04x", ch.code))
                    } else {
                        out.append(ch)
                    }
                }
            }
            out.append('"')
        }

        fun escapeToString(s: String): String = StringBuilder().also { escape(it, s) }.toString()
    }
}
