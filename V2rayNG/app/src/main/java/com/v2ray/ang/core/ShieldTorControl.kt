package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.File
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Post-bootstrap check through Tor's ControlPort, modelled on UAC's TorExitCountry:
 * GETCONF ExitNodes -> re-apply with SETCONF if needed -> observe built circuits.
 * A built circuit is not proof of the exit used by an application's stream. Observations
 * must never tear down active circuits or trigger repeated NEWNYM requests.
 */
internal object ShieldTorControl {
    const val CONTROL_PORT = 1822
    const val COOKIE_NAME = "control_auth_cookie"
    private const val MAX_ATTEMPTS = 5

    fun verifyExit(dir: File, wanted: String?) {
        val country = countryCode(wanted) ?: return
        LogUtil.w(AppConfig.TAG, "ShieldTorControl: observe requested country=$country")
        val cookie = File(dir, COOKIE_NAME)
        try {
            Session().use { s ->
                s.authenticate(cookie)
                // Re-apply the country rule in case the running Tor drifted from torrc.
                if (!s.getConfExits().contains(country)) {
                    s.command("SETCONF ExitNodes={$country} StrictNodes=1")
                    LogUtil.w(AppConfig.TAG, "ShieldTorControl: re-applied ExitNodes {$country}")
                }
                for (attempt in 1..MAX_ATTEMPTS) {
                    val actual = s.currentExitCountry()
                    if (actual == country) {
                        LogUtil.w(AppConfig.TAG, "ShieldTorControl: built circuit country=$actual (not stream verification)")
                        return
                    }
                    LogUtil.w(AppConfig.TAG, "ShieldTorControl: observed ${actual ?: "unknown"}, want $country; preserving circuits (attempt $attempt)")
                    if (attempt < MAX_ATTEMPTS) Thread.sleep(3000)
                }
                LogUtil.w(AppConfig.TAG, "ShieldTorControl: requested country not observed; no circuits closed")
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (e: Exception) {
            LogUtil.w(AppConfig.TAG, "ShieldTorControl: check failed: $e")
        }
    }

    internal fun countryCode(value: String?): String? = value?.trim()?.uppercase(java.util.Locale.ROOT)
        ?.takeIf { Regex("[A-Z]{2}").matches(it) }

    private const val MIDDLE_COUNT = 60
    private const val MIN_USABLE = 10

    /** Pins MiddleNodes to the fastest Fast+Stable relays (as UAC's TorFastRelays does). */
    fun applyFastMiddles(dir: File) {
        try {
            Session().use { s ->
                s.authenticate(File(dir, COOKIE_NAME))
                val fps = pickMiddles(s.command("GETINFO ns/all"))
                if (fps.size < MIN_USABLE) {
                    LogUtil.w(AppConfig.TAG, "ShieldTorControl: only ${fps.size} fast relays, MiddleNodes unset")
                    return
                }
                s.command("SETCONF MiddleNodes=" + fps.joinToString(",") { "$" + it })
                LogUtil.w(AppConfig.TAG, "ShieldTorControl: MiddleNodes set to ${fps.size} fast relays")
            }
        } catch (e: Exception) {
            LogUtil.w(AppConfig.TAG, "ShieldTorControl: fast middles failed: $e")
        }
    }

    private class R(val fp: String, val bw: Long, val flags: Set<String>)

    private fun pickMiddles(body: List<String>): List<String> {
        val out = ArrayList<R>()
        var fp: String? = null
        var flags: Set<String> = emptySet()
        for (raw in body) {
            val line = raw.trim()
            when {
                line.startsWith("r ") -> {
                    fp = line.split(' ').getOrNull(2)?.let { b64 ->
                        runCatching {
                            val bytes = android.util.Base64.decode(b64 + "=".repeat((4 - b64.length % 4) % 4), android.util.Base64.DEFAULT)
                            bytes.joinToString("") { "%02X".format(it) }
                        }.getOrNull()?.takeIf { it.length == 40 }
                    }
                    flags = emptySet()
                }
                line.startsWith("s ") -> flags = line.substring(2).split(' ').toSet()
                line.startsWith("w ") -> {
                    val bw = Regex("Bandwidth=(\\d+)").find(line)?.groupValues?.get(1)?.toLongOrNull()
                    val f = fp
                    if (f != null && bw != null) out += R(f, bw, flags)
                    fp = null
                }
            }
        }
        return out.filter { "Fast" in it.flags && "Stable" in it.flags && "Running" in it.flags && "Valid" in it.flags && "BadExit" !in it.flags }
            .sortedByDescending { it.bw }.take(MIDDLE_COUNT).map { it.fp }
    }

    private class Session : AutoCloseable {
        private val sock = Socket().apply { connect(InetSocketAddress("127.0.0.1", CONTROL_PORT), 5000); soTimeout = 15000 }
        private val reader = BufferedReader(InputStreamReader(sock.getInputStream()))
        private val writer = BufferedWriter(OutputStreamWriter(sock.getOutputStream()))

        fun authenticate(cookie: File) {
            val hex = cookie.readBytes().joinToString("") { "%02x".format(it) }
            command("AUTHENTICATE $hex")
        }

        /** Sends one command and returns the payload lines (multi-line "+" blocks are flattened). */
        fun command(cmd: String): List<String> {
            writer.write(cmd + "\r\n"); writer.flush()
            val out = mutableListOf<String>()
            while (true) {
                val line = reader.readLine() ?: throw IllegalStateException("control connection closed")
                if (line.length >= 4 && line[3] == '+') {
                    // Data block: payload lines follow until a single "." line.
                    out += line.substring(4)
                    while (true) {
                        val d = reader.readLine() ?: throw IllegalStateException("control connection closed")
                        if (d == ".") break
                        out += d
                    }
                    continue
                }
                if (line.length >= 4 && line[3] == '-') { out += line.substring(4); continue }
                if (line.startsWith("250")) return out
                throw IllegalStateException("control error: $line")
            }
        }

        /** Country codes currently in GETCONF ExitNodes. */
        fun getConfExits(): Set<String> =
            command("GETCONF ExitNodes").joinToString(" ").let { Regex("[A-Z]{2}").findAll(it).map { m -> m.value }.toSet() }

        /** Country of the exit used by the most recent built general circuit, or null if unknown. */
        fun currentExitCountry(): String? {
            val circuits = command("GETINFO circuit-status").filter { " BUILT " in it && "PURPOSE=GENERAL" in it }
            val last = circuits.lastOrNull() ?: return null
            // Path looks like "$FP~name,$FP~name,$FP~name"; the last hop is the exit.
            val fp = last.split(" ").firstOrNull { it.startsWith("$") && it.length > 1 }
                ?.split(",")?.lastOrNull()?.removePrefix("$")?.substringBefore("~")?.substringBefore("=")
                ?.takeIf { it.length == 40 } ?: return null
            val ip = ipOf(fp) ?: return null
            val cc = command("GETINFO ip-to-country/$ip").firstOrNull()?.substringAfter("=")?.trim()?.uppercase() ?: return null
            return countryCode(cc)
        }

        /** Relay IP: ns/id, then desc/id, then a scan of ns/all (some Tor builds reject ns/id). */
        private fun ipOf(fp: String): String? {
            runCatching { command("GETINFO ns/id/$fp") }.getOrNull()
                ?.firstOrNull { it.startsWith("r ") }?.split(" ")?.getOrNull(6)?.let { return it }
            runCatching { command("GETINFO desc/id/$fp") }.getOrNull()
                ?.firstOrNull { it.startsWith("router ") }?.split(" ")?.getOrNull(2)?.let { return it }
            val want = runCatching {
                android.util.Base64.encodeToString(fp.chunked(2).map { it.toInt(16).toByte() }.toByteArray(), android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
            }.getOrNull() ?: return null
            return runCatching { command("GETINFO ns/all") }.getOrNull()
                ?.firstOrNull { it.startsWith("r ") && it.split(" ").getOrNull(2) == want }?.split(" ")?.getOrNull(6)
        }

        override fun close() { try { sock.close() } catch (_: Exception) {} }
    }
}
