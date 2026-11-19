package com.v2ray.ang.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlin.concurrent.thread

/** One native Shield Tor lifetime. Owns control/probe sockets and its worker; stop never opens a new connection. */
internal class ShieldBridgeSession(
    private val cookie: File,
    private val candidates: List<String>,
    private val socksPort: Int,
    private val scope: String?,
    private val currentScope: () -> String?,
    private val alive: () -> Boolean,
    private val alreadyReady: () -> Boolean,
    private val onReady: () -> Unit,
    private val wantedExit: String?,
) : AutoCloseable {
    private val cancelled = AtomicBoolean(false)
    @Volatile private var control: ShieldTorControl.Session? = null
    @Volatile private var probe: Socket? = null
    @Volatile private var worker: Thread? = null
    private fun active() = !cancelled.get() && alive() && !Thread.currentThread().isInterrupted
    private fun sameNetwork() = scope != null && currentScope() == scope
    private fun now() = System.nanoTime() / 1_000_000

    fun start() {
        worker = thread(name = "shield-tor-bridges", isDaemon = true, start = false) { run() }
        worker?.start()
        if (!active()) close()
    }

    private fun run() {
        val started = now()
        try {
            // Authenticate once. Keeping this connection pins every command to this daemon, even if its port is reused.
            var connected: ShieldTorControl.Session? = null
            while (active() && now() - started < 10_000L && connected == null) {
                try {
                    if (cookie.isFile) {
                        val s = ShieldTorControl.Session(3000)
                        control = s
                        if (!active()) { s.close(); return }
                        s.authenticate(cookie)
                        connected = s
                    }
                } catch (_: Exception) {
                    control?.close()
                    control = null
                }
                if (connected == null) Thread.sleep(250)
            }
            val s = connected ?: return
            var attempt = 0
            var attemptStart = started
            var exhausted = false
            while (active()) {
                val progress = s.bootstrapProgress() ?: return // Unknown state must never trigger a switch.
                if (progress == 100 || alreadyReady()) {
                    onReady()
                    ShieldTorControl.applyFastMiddles(s, ::active)
                    ShieldTorControl.verifyExit(s, wantedExit, ::active)
                    measure(s, candidates[attempt])
                    return
                }
                val elapsed = now() - attemptStart
                if (!exhausted && elapsed >= ShieldBridgeQuality.ATTEMPT_MS) {
                    // A network handover is not evidence that a bridge failed. Leave recovery to the service.
                    if (!sameNetwork()) return
                    // Recheck at the boundary; never deliberately rotate a bootstrapped connection.
                    val boundaryProgress = s.bootstrapProgress() ?: return
                    if (boundaryProgress == 100 || alreadyReady()) continue
                    if (!active()) return
                    if (ShieldBridgeQuality.shouldFallback(false, elapsed, attempt, candidates.size)) {
                        val previous = candidates[attempt]
                        s.replaceBridge(candidates[attempt + 1])
                        if (!active()) return
                        if (sameNetwork()) ShieldBridgeRanker.quality.record(scope, previous, null, bootstrapFailed = true)
                        attempt++
                        attemptStart = now()
                        LogUtil.w(AppConfig.TAG, "ShieldTor: bootstrap fallback ${attempt + 1}/${candidates.size}; circuits preserved")
                    } else {
                        // Stop rotating, but let the final bridge finish until the service's bounded warm-up expires.
                        if (sameNetwork()) ShieldBridgeRanker.quality.record(scope, candidates[attempt], null, bootstrapFailed = true)
                        exhausted = true
                        LogUtil.w(AppConfig.TAG, "ShieldTor: bridge attempt budget exhausted; no more switches")
                    }
                }
                Thread.sleep(1000)
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (e: Exception) {
            if (active()) LogUtil.w(AppConfig.TAG, "ShieldTor: bridge monitoring stopped (${e.javaClass.simpleName}); connection preserved")
        } finally {
            control?.close()
            probe?.runCatching { close() }
        }
    }

    /** Full-test mode: time a ~256 KB download through Tor; failure costs a fixed penalty so slow paths rank last. */
    private fun downloadMs(): Long {
        val socket = Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort)))
        probe = socket
        val began = System.nanoTime()
        return try {
            socket.soTimeout = 12_000
            socket.connect(InetSocketAddress.createUnresolved("speed.cloudflare.com", 443), 12_000)
            ((SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(socket, "speed.cloudflare.com", 443, true) as SSLSocket).use { tls ->
                tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                tls.soTimeout = 12_000
                tls.startHandshake()
                tls.getOutputStream().apply {
                    write("GET /__down?bytes=262144 HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    flush()
                }
                val buf = ByteArray(16384)
                var total = 0L
                val input = tls.getInputStream()
                while (true) { val n = input.read(buf); if (n < 0) break; total += n }
                if (total >= 200_000) (System.nanoTime() - began) / 1_000_000 else 20_000L
            }
        } catch (_: Exception) {
            20_000L
        } finally {
            runCatching { socket.close() }
            probe = null
        }
    }

    private fun measure(s: ShieldTorControl.Session, bridge: String) {
        if (!active() || !sameNetwork() || !s.usesOnly(bridge)) return
        val values = mutableListOf<Long>()
        val timer = Executors.newSingleThreadScheduledExecutor { task ->
            Thread(task, "shield-tor-quality-deadline").apply { isDaemon = true }
        }
        try {
            repeat(3) {
                if (!active() || !sameNetwork()) return
                val socket = Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort)))
                probe = socket
                val deadline = timer.schedule({ runCatching { socket.close() } }, 10, TimeUnit.SECONDS)
                val began = System.nanoTime()
                try {
                    if (!active()) return
                    socket.soTimeout = 10_000
                    // Unresolved host delegates DNS to Tor, not the Android system resolver.
                    socket.connect(InetSocketAddress.createUnresolved("www.gstatic.com", 443), 10_000)
                    ((SSLSocketFactory.getDefault() as SSLSocketFactory)
                        .createSocket(socket, "www.gstatic.com", 443, true) as SSLSocket).use { tls ->
                        tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                        tls.soTimeout = 10_000
                        tls.startHandshake()
                        tls.getOutputStream().apply {
                            write("GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                            flush()
                        }
                        val status = StringBuilder()
                        val input = tls.getInputStream()
                        while (status.length < 512 && !status.endsWith("\r\n")) {
                            val ch = input.read()
                            if (ch < 0) break
                            status.append(ch.toChar())
                        }
                        if (Regex("HTTP/1\\.[01] 204(?: [^\\r\\n]*)?\\r\\n").matches(status)) {
                            values += ((System.nanoTime() - began) / 1_000_000).coerceAtLeast(1)
                        }
                    }
                } catch (_: Exception) {
                    // Destination/exit failures are not bridge failures and never cause fallback.
                } finally {
                    deadline.cancel(false)
                    runCatching { socket.close() }
                    probe = null
                }
            }
            // Confirm that no old/other guard survived a pre-bootstrap switch before assigning this path observation.
            if (active() && sameNetwork() && values.size >= 2 && s.usesOnly(bridge)) {
                var median = values.sorted()[values.size / 2]
                if (ShieldBridgeRanker.fullTest()) median += downloadMs()
                ShieldBridgeRanker.quality.record(scope, bridge, median)
                com.v2ray.ang.handler.MmkvManager.encodeSettings(ShieldBridgeRanker.PREF_LAST_GOOD, bridge)
                LogUtil.w(AppConfig.TAG, "ShieldTor: HTTPS path observation ${median}ms (${values.size}/3 samples)")
            }
        } finally {
            timer.shutdownNow()
        }
    }

    /** Tracks only physical Internet networks, not our own VPN; registration belongs to the native session. */
    class NetworkScope(context: Context) : AutoCloseable {
        private val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        private val networks = mutableSetOf<Long>()
        private var closed = false
        private var generation = 0L
        private val first = java.util.concurrent.CountDownLatch(1)
        private val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                synchronized(networks) { if (!closed && networks.add(network.networkHandle)) generation++ }
                first.countDown()
            }
            override fun onLost(network: Network) {
                synchronized(networks) { if (networks.remove(network.networkHandle)) generation++ }
            }
        }
        init {
            connectivity.registerNetworkCallback(NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback)
        }
        fun awaitInitial() { first.await(1, TimeUnit.SECONDS) }
        fun key(exit: String?): String? = synchronized(networks) {
            // Multiple physical routes cannot be attributed reliably without binding Tor's transport.
            if (closed || networks.size != 1) null else "${networks.single()}:$generation:" + (exit ?: "smart")
        }
        override fun close() {
            synchronized(networks) { closed = true; networks.clear() }
            runCatching { connectivity.unregisterNetworkCallback(callback) }
            first.countDown()
        }
    }

    override fun close() {
        cancelled.set(true)
        control?.close()
        probe?.runCatching { close() }
        worker?.interrupt()
    }
}
