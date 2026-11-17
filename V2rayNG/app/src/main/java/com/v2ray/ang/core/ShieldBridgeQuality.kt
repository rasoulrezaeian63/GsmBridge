package com.v2ray.ang.core

/** Process-local, expiring observations; never persists bridge URLs or transfers scores between networks/exits. */
internal class ShieldBridgeQuality(private val now: () -> Long = { System.nanoTime() / 1_000_000 }) {
    private data class Key(val scope: String, val bridge: String)
    private data class Sample(val at: Long, val latencyMs: Long?, val failed: Boolean)
    private val samples = LinkedHashMap<Key, Sample>()

    @Synchronized
    fun record(scope: String?, bridge: String, latencyMs: Long?, bootstrapFailed: Boolean = false) {
        if (scope == null || (!bootstrapFailed && (latencyMs == null || latencyMs <= 0))) return
        val key = Key(scope, bridge)
        samples.remove(key)
        samples[key] = Sample(now(), latencyMs, bootstrapFailed)
        while (samples.size > 128) samples.remove(samples.keys.first())
    }

    /** Successful TLS/Upgrade probes remain ahead of unprobed candidates (the caller supplies each group). */
    @Synchronized
    fun order(scope: String?, bridges: List<String>): List<String> {
        if (scope == null) return bridges
        val time = now()
        samples.entries.removeAll { time - it.value.at >= TTL_MS }
        fun sample(bridge: String) = samples[Key(scope, bridge)]
        return bridges.sortedWith(compareBy<String> {
            val s = sample(it)
            when {
                s == null -> 1
                s.failed && time - s.at < COOLDOWN_MS -> 2
                s.failed -> 1
                else -> 0
            }
        }.thenBy { sample(it)?.takeUnless { s -> s.failed }?.latencyMs ?: Long.MAX_VALUE })
    }

    companion object {
        const val TTL_MS = 30 * 60_000L
        const val COOLDOWN_MS = 5 * 60_000L
        const val MAX_ATTEMPTS = 3
        const val ATTEMPT_MS = 60_000L
        const val START_BUDGET_MS = MAX_ATTEMPTS * ATTEMPT_MS + 20_000L

        fun shouldFallback(ready: Boolean, elapsedMs: Long, attempt: Int, candidates: Int): Boolean =
            !ready && attempt >= 0 && elapsedMs >= ATTEMPT_MS && attempt + 1 < minOf(candidates, MAX_ATTEMPTS)
    }
}
