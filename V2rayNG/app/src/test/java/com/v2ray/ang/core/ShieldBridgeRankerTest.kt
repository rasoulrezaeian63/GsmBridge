package com.v2ray.ang.core

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.URI

class ShieldBridgeRankerTest {
    @Test
    fun `few successful bridges are never discarded for fallback`() {
        assertEquals(listOf("b", "a", "c"), ShieldBridgeRanker.select(listOf("a", "b", "c"), listOf("b"), 3))
    }

    @Test
    fun `selection handles duplicates limits and unknown results`() {
        assertEquals(listOf("c", "b"), ShieldBridgeRanker.select(listOf("a", "b", "c", "a"), listOf("c", "b", "c", "x"), 2))
        assertEquals(emptyList<String>(), ShieldBridgeRanker.select(listOf("a"), listOf("a"), 0))
        assertEquals(listOf("a"), ShieldBridgeRanker.select(listOf("a", "a"), emptyList(), 8))
        assertEquals(emptyList<String>(), ShieldBridgeRanker.pick(emptyList(), 8))
        assertEquals(emptyList<String>(), ShieldBridgeRanker.pick(listOf("a"), -1))
    }

    @Test
    fun `probe uses exact encoded path query and nondefault port`() {
        val uri = ShieldBridgeRanker.endpoint("webtunnel 192.0.2.1:1 FP url=https://example.org:8443/a%2Fb?q=x%20y")!!
        val request = ShieldBridgeRanker.request(uri, "test-key")
        assertTrue(request.startsWith("GET /a%2Fb?q=x%20y HTTP/1.1\r\nHost: example.org:8443\r\n"))
        assertTrue(request.contains("Connection: Upgrade\r\nUpgrade: websocket\r\n"))
        assertTrue(ShieldBridgeRanker.request(URI("https://example.org"), "key").startsWith("GET / HTTP/1.1"))
    }

    @Test
    fun `unsafe or malformed endpoints cannot be probed`() {
        for (url in listOf("http://example.org/a", "https://user:pw@example.org/a", "https://example.org/a#fragment", "https://example.org:99999/a", "garbage")) {
            assertNull(ShieldBridgeRanker.endpoint("url=$url"), url)
        }
        assertNull(ShieldBridgeRanker.endpoint("noturl=https://example.org"))
    }

    @Test
    fun `HTTP errors and captive portals are not live upgrades`() {
        assertTrue(ShieldBridgeRanker.isSwitchingProtocols("HTTP/1.1 101 Switching Protocols"))
        assertTrue(ShieldBridgeRanker.isSwitchingProtocols("HTTP/1.1 101"))
        for (line in listOf("HTTP/1.1 200 OK", "HTTP/1.1 301 Moved", "HTTP/1.1 403 Forbidden", "HTTP/1.1 1010 Nope", "garbage 101")) {
            assertFalse(ShieldBridgeRanker.isSwitchingProtocols(line), line)
        }
    }
}
