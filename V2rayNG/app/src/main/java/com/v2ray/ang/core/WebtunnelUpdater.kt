package com.v2ray.ang.core

import com.v2ray.ang.AngApplication
import com.v2ray.ang.dto.UrlContentRequest
import com.v2ray.ang.util.HttpUtil
import java.io.File

/** Downloads the webtunnel bridge list from [URL], validates it and stores it for [WebtunnelBridges]. */
object WebtunnelUpdater {
    const val URL = "https://netlixy.ir/dl/backhaul/bridge.txt"
    private const val FILE = "webtunnel_bridges.txt"
    private val LINE = Regex("""^webtunnel\s+\S+\s+[0-9A-Fa-f]{40}(\s+\S+)*\s+url=https?://\S+.*$""")

    @Volatile private var autoDone = false

    fun parse(text: String): List<String> = text.lineSequence()
        .map { it.trim().removePrefix("Bridge ").removePrefix("bridge ").trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") && LINE.matches(it) }
        .distinct().toList()

    /** Saved list (empty if none). */
    fun saved(): List<String> = try {
        val f = File(AngApplication.application.filesDir, FILE)
        if (f.exists()) parse(f.readText()) else emptyList()
    } catch (_: Exception) { emptyList() }

    /** @return number of bridges stored, or -1 on failure (the old list is kept). Blocking: call off the main thread. */
    fun update(): Int = try {
        val body = HttpUtil.getUrlContent(UrlContentRequest(url = URL, timeout = 15000)).orEmpty()
        val lines = parse(body)
        if (lines.isEmpty()) -1 else {
            val f = File(AngApplication.application.filesDir, FILE)
            val tmp = File(f.parentFile, "$FILE.tmp")
            tmp.writeText(lines.joinToString("\n"))
            if (!tmp.renameTo(f)) { f.writeText(tmp.readText()); tmp.delete() }
            lines.size
        }
    } catch (_: Exception) { -1 }

    /** One silent update per app process start. */
    fun autoOnce() {
        if (autoDone) return
        autoDone = true
        Thread({ update() }, "webtunnel-auto-update").apply { isDaemon = true }.start()
    }
}
