package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Probe ownership belongs to this synchronous scan; sockets are closed when its budget expires. */
internal object ShieldBridgeRanker {
    private const val TIMEOUT_MS = 3000
    private const val SCAN_SECONDS = 8L
    private const val MAX_PROBES = 48

    fun pick(all: List<String>, count: Int): List<String> {
        if (count <= 0 || all.isEmpty()) return emptyList()
        val candidates = all.distinct().shuffled()
        val sockets = ConcurrentHashMap.newKeySet<Socket>()
        val stopped = AtomicBoolean(false)
        val pool = Executors.newFixedThreadPool(8) { task ->
            Thread(task, "shield-webtunnel-probe").apply { isDaemon = true }
        }
        return try {
            val tasks = candidates.take(MAX_PROBES).map { line ->
                Callable { line to connectMs(line, sockets, stopped) }
            }
            val results = pool.invokeAll(tasks, SCAN_SECONDS, TimeUnit.SECONDS)
                .mapNotNull { f -> if (f.isCancelled) null else runCatching { f.get() }.getOrNull() }
            val ok = results.filter { it.second != null }.sortedBy { it.second }.map { it.first }
            LogUtil.w(AppConfig.TAG, "ShieldTor: WebTunnel upgrades ${ok.size}/${tasks.size}")
            select(candidates, ok, count)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw e
        } catch (e: Exception) {
            // Do not log exception messages: they may contain a private bridge URL.
            LogUtil.w(AppConfig.TAG, "ShieldTor: bridge scan failed (${e.javaClass.simpleName})")
            select(candidates, emptyList(), count)
        } finally {
            stopped.set(true)
            sockets.forEach { runCatching { it.close() } }
            pool.shutdownNow()
        }
    }

    /** Keep every successful probe first, even if fewer than four bridges answered. */
    internal fun select(all: List<String>, successful: List<String>, count: Int): List<String> {
        if (count <= 0) return emptyList()
        val allowed = all.toSet()
        return (successful.filter { it in allowed } + all).distinct().take(count)
    }

    internal fun endpoint(line: String): URI? {
        val url = Regex("""(?:^|\s)url=(\S+)""").find(line)?.groupValues?.get(1) ?: return null
        val uri = runCatching { URI(url) }.getOrNull() ?: return null
        // Never send bridge paths over plaintext or to user-info/fragment URLs.
        return uri.takeIf {
            it.scheme.equals("https", ignoreCase = true) && !it.host.isNullOrBlank() &&
                it.rawUserInfo == null && it.rawFragment == null &&
                (it.port == -1 || it.port in 1..65535)
        }
    }

    internal fun request(uri: URI, key: String): String {
        val path = uri.rawPath.ifEmpty { "/" } + (uri.rawQuery?.let { "?$it" } ?: "")
        val authority = uri.host + (if (uri.port == -1 || uri.port == 443) "" else ":${uri.port}")
        return "GET $path HTTP/1.1\r\nHost: $authority\r\n" +
            "User-Agent: Mozilla/5.0\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
            "Sec-WebSocket-Key: $key\r\nSec-WebSocket-Version: 13\r\n\r\n"
    }

    internal fun isSwitchingProtocols(status: String): Boolean =
        Regex("""HTTP/1\.[01] 101(?: .*)?""").matches(status)

    private fun connectMs(line: String, sockets: MutableSet<Socket>, stopped: AtomicBoolean): Long? {
        val uri = endpoint(line) ?: return null
        val started = System.nanoTime()
        val deadline = started + TimeUnit.MILLISECONDS.toNanos(TIMEOUT_MS.toLong())
        fun remaining(): Int {
            check(!stopped.get() && !Thread.currentThread().isInterrupted)
            val ms = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
            check(ms > 0)
            return ms.coerceAtMost(TIMEOUT_MS.toLong()).toInt()
        }
        val plain = Socket()
        sockets.add(plain)
        try {
            remaining()
            // JVM DNS lookup itself is not interruptible; recheck the deadline after resolution.
            val address = InetSocketAddress(uri.host, if (uri.port > 0) uri.port else 443)
            plain.connect(address, remaining())
            plain.soTimeout = remaining()
            ((SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(plain, uri.host, address.port, true) as SSLSocket).use { tls ->
                // Platform trust store plus HTTPS hostname validation; no trustAll fallback.
                tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                tls.soTimeout = remaining()
                tls.startHandshake()
                val key = Base64.getEncoder().encodeToString(ByteArray(16).also { SecureRandom().nextBytes(it) })
                tls.getOutputStream().apply { write(request(uri, key).toByteArray(Charsets.US_ASCII)); flush() }
                val status = StringBuilder()
                val input = tls.getInputStream()
                while (status.length < 512) {
                    tls.soTimeout = remaining()
                    val next = input.read()
                    if (next < 0) return null
                    status.append(next.toChar())
                    if (status.endsWith("\r\n")) {
                        return if (isSwitchingProtocols(status.dropLast(2).toString()))
                            (System.nanoTime() - started) / 1_000_000 else null
                    }
                }
            }
        } catch (_: Exception) {
            // Individual failures are expected; only aggregate counts are logged to protect bridge URLs.
        } finally {
            runCatching { plain.close() }
            sockets.remove(plain)
        }
        return null
    }
}
