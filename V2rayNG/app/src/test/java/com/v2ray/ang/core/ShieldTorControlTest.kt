package com.v2ray.ang.core

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ShieldTorControlTest {
    @Test
    fun `guard attribution rejects unknown mixed and malformed circuits`() {
        val a = "A".repeat(40)
        val b = "B".repeat(40)
        val bridge = "webtunnel 192.0.2.1:443 $a url=https://example.org/path"
        fun circuit(fp: String) = "1 BUILT \$$fp~guard,\$$b~exit PURPOSE=GENERAL"
        assertTrue(ShieldTorControl.onlyGuard(listOf(circuit(a)), bridge))
        assertFalse(ShieldTorControl.onlyGuard(emptyList(), bridge))
        assertFalse(ShieldTorControl.onlyGuard(listOf(circuit(a), circuit(b)), bridge))
        assertFalse(ShieldTorControl.onlyGuard(listOf(circuit(a), "2 BUILT unknown PURPOSE=GENERAL"), bridge))
        assertFalse(ShieldTorControl.onlyGuard(listOf(circuit(a)), "webtunnel without-fingerprint"))
    }

    @Test
    fun `bridge control argument cannot inject commands`() {
        assertEquals("\"a\\\"b\\\\c\"", ShieldTorControl.quotedBridge("a\"b\\c"))
        for (line in listOf("", "bridge\r\nSIGNAL NEWNYM", "bridge\u0000")) {
            assertThrows(IllegalArgumentException::class.java) { ShieldTorControl.quotedBridge(line) }
        }
    }

    @Test
    fun `unknown geoip values are not countries`() {
        for (value in listOf(null, "", "??", "A1", "UNKNOWN", "{DE}", "DE\r\nSIGNAL NEWNYM")) {
            assertNull(ShieldTorControl.countryCode(value))
        }
    }

    @Test
    fun `country comparison is normalized`() {
        assertEquals("DE", ShieldTorControl.countryCode(" de "))
        assertEquals("US", ShieldTorControl.countryCode("US"))
    }
}
