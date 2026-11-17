package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Orders webtunnel bridges by the TCP connect time to the real endpoint (the url= host), dropping unreachable ones. */
internal object ShieldBridgeRanker {
    private const val TIMEOUT_MS = 3000
    private const val MIN_REACHABLE = 4

    fun pick(all: List<String>, count: Int): List<String> {
        val fallback = { all.shuffled().take(count) }
        return try {
            val pool = Executors.newFixedThreadPool(16)
            try {
                val tasks = all.map { line -> Callable { line to connectMs(line) } }
                val results = pool.invokeAll(tasks, 8, TimeUnit.SECONDS)
                    .mapNotNull { f -> if (f.isCancelled) null else runCatching { f.get() }.getOrNull() }
                val ok = results.filter { it.second != null }.sortedBy { it.second }
                LogUtil.w(AppConfig.TAG, "ShieldTor: bridges reachable ${ok.size}/${all.size}, best=${ok.firstOrNull()?.second}ms")
                if (ok.size < MIN_REACHABLE) fallback()
                else {
                    // Take from the fastest half, shuffled, so one bridge is not hammered by every user.
                    val top = ok.take(maxOf(count, ok.size / 2)).map { it.first }.shuffled().take(count)
                    // Keep the fastest one first.
                    listOf(ok.first().first) + top.filter { it != ok.first().first }.take(count - 1)
                }
            } finally { pool.shutdownNow() }
        } catch (e: Exception) {
            LogUtil.w(AppConfig.TAG, "ShieldTor: bridge ranking failed: $e")
            fallback()
        }
    }

    private fun connectMs(line: String): Long? {
        val url = Regex("""url=(\S+)""").find(line)?.groupValues?.get(1) ?: return null
        val uri = runCatching { URI(url) }.getOrNull() ?: return null
        val host = uri.host ?: return null
        val port = if (uri.port > 0) uri.port else 443
        val t0 = System.nanoTime()
        return try {
            Socket().use { it.connect(InetSocketAddress(host, port), TIMEOUT_MS) }
            (System.nanoTime() - t0) / 1_000_000
        } catch (_: Exception) { null }
    }
}
