package com.v2ray.ang.core

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ShieldBridgeQualityTest {
    @Test
    fun `scores stay inside network and exit scope`() {
        val quality = ShieldBridgeQuality { 0L }
        quality.record("wifi:DE", "b", 100)
        assertEquals(listOf("b", "a"), quality.order("wifi:DE", listOf("a", "b")))
        for (scope in listOf(null, "cell:DE", "wifi:US")) {
            assertEquals(listOf("a", "b"), quality.order(scope, listOf("a", "b")))
        }
    }

    @Test
    fun `successful path samples expire`() {
        var time = 0L
        val quality = ShieldBridgeQuality { time }
        quality.record("n", "b", 100)
        time = ShieldBridgeQuality.TTL_MS - 1
        assertEquals(listOf("b", "a"), quality.order("n", listOf("a", "b")))
        time++
        assertEquals(listOf("a", "b"), quality.order("n", listOf("a", "b")))
    }

    @Test
    fun `bootstrap failure cooldown expires without permanent exclusion`() {
        var time = 0L
        val quality = ShieldBridgeQuality { time }
        quality.record("n", "a", null, bootstrapFailed = true)
        assertEquals(listOf("b", "a"), quality.order("n", listOf("a", "b")))
        time = ShieldBridgeQuality.COOLDOWN_MS
        assertEquals(listOf("a", "b"), quality.order("n", listOf("a", "b")))
    }

    @Test
    fun `invalid and failed destination probes do not penalize bridge`() {
        val quality = ShieldBridgeQuality { 0L }
        quality.record("n", "b", 200)
        for (latency in listOf(null, 0L, -1L)) quality.record("n", "b", latency)
        quality.record(null, "a", 1)
        assertEquals(listOf("b", "a"), quality.order("n", listOf("a", "b")))
    }

    @Test
    fun `latency sorts only measured candidates`() {
        val quality = ShieldBridgeQuality { 0L }
        quality.record("n", "a", 500)
        quality.record("n", "b", 100)
        assertEquals(listOf("b", "a", "c"), quality.order("n", listOf("c", "a", "b")))
    }

    @Test
    fun `fallback respects readiness time and three attempt ceiling`() {
        val elapsed = ShieldBridgeQuality.ATTEMPT_MS
        assertFalse(ShieldBridgeQuality.shouldFallback(true, elapsed, 0, 3))
        assertFalse(ShieldBridgeQuality.shouldFallback(false, elapsed - 1, 0, 3))
        assertTrue(ShieldBridgeQuality.shouldFallback(false, elapsed, 0, 3))
        assertTrue(ShieldBridgeQuality.shouldFallback(false, elapsed, 1, 3))
        assertFalse(ShieldBridgeQuality.shouldFallback(false, elapsed, 2, 10))
        assertFalse(ShieldBridgeQuality.shouldFallback(false, elapsed, 0, 1))
        assertFalse(ShieldBridgeQuality.shouldFallback(false, elapsed, -1, 3))
    }
}
