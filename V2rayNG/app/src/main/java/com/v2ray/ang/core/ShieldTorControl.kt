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
 * GETCONF ExitNodes -> re-apply with SETCONF if needed -> inspect the built exit -> NEWNYM and retry on mismatch.
 * Everything is checked with Tor's own GeoIP (ip-to-country), so no external site is involved.
 */
internal object ShieldTorControl {
    const val CONTROL_PORT = 1822
    const val COOKIE_NAME = "control_auth_cookie"
    private const val MAX_ATTEMPTS = 5

    fun verifyExit(dir: File, wanted: String?) {
        LogUtil.w(AppConfig.TAG, "ShieldTorControl: start, wanted=$wanted")
        if (wanted == null) return
        val cookie = File(dir, COOKIE_NAME)
        try {
            Session().use { s ->
                s.authenticate(cookie)
                // Re-apply the country rule in case the running Tor drifted from torrc.
                if (!s.getConfExits().contains(wanted)) {
                    s.command("SETCONF ExitNodes={$wanted} StrictNodes=1")
                    LogUtil.w(AppConfig.TAG, "ShieldTorControl: re-applied ExitNodes {$wanted}")
                }
                for (attempt in 1..MAX_ATTEMPTS) {
                    val actual = s.currentExitCountry()
                    if (actual == wanted) {
                        LogUtil.w(AppConfig.TAG, "ShieldTorControl: exit verified $actual (attempt $attempt)")
                        return
                    }
                    LogUtil.w(AppConfig.TAG, "ShieldTorControl: exit is ${actual ?: "unknown"}, want $wanted; NEWNYM (attempt $attempt)")
                    s.closeBuiltCircuits()
                    s.command("SIGNAL NEWNYM")
                    Thread.sleep(3000)
                }
                LogUtil.w(AppConfig.TAG, "ShieldTorControl: could not get an exit in $wanted after $MAX_ATTEMPTS attempts")
            }
        } catch (e: Exception) {
            LogUtil.w(AppConfig.TAG, "ShieldTorControl: check failed: $e")
        }
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

        /** Closes every built circuit so existing streams cannot keep the old exit. */
        fun closeBuiltCircuits() {
            val ids = command("GETINFO circuit-status")
                .filter { " BUILT " in it }
                .mapNotNull { it.trim().split(" ").firstOrNull()?.takeIf { id -> id.all(Char::isDigit) } }
            for (id in ids) {
                try { command("CLOSECIRCUIT $id") } catch (e: Exception) {
                    LogUtil.w(AppConfig.TAG, "ShieldTorControl: CLOSECIRCUIT $id failed: $e")
                }
            }
            LogUtil.w(AppConfig.TAG, "ShieldTorControl: closed ${ids.size} circuits")
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
            val ns = command("GETINFO ns/id/$fp")
            // v3 router status: "r nick identity digest date time IP ORPort DirPort"
            val ip = ns.firstOrNull { it.startsWith("r ") }?.split(" ")?.getOrNull(6) ?: return null
            val cc = command("GETINFO ip-to-country/$ip").firstOrNull()?.substringAfter("=")?.trim()?.uppercase() ?: return null
            return cc.takeIf { it.length == 2 }
        }

        override fun close() { try { sock.close() } catch (_: Exception) {} }
    }
}
