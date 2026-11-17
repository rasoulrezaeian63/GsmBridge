package com.v2ray.ang.ui.main

import java.util.Locale

/** Tor exit countries offered by the Shield Tunnel picker; the empty code is Automatic. */
object ShieldCountries {
    private val CODES = listOf(
        "DE", "NL", "FR", "GB", "SE", "CH", "AT", "NO", "FI", "DK", "BE", "LU", "IE", "IS",
        "ES", "IT", "PT", "PL", "CZ", "RO", "BG", "HU", "MD", "UA", "LV", "LT", "EE",
        "US", "CA", "JP", "SG", "HK", "AU", "NZ", "BR", "AR", "CL", "ZA", "IN", "IL",
        "KR", "TR", "AE", "AM", "AF", "AZ",
    )

    /** The codes, each with its name in the app's language, sorted by that name. */
    fun all(locale: Locale): List<Pair<String, String>> =
        CODES.map { it to Locale("", it).getDisplayCountry(locale) }.sortedBy { it.second }

    fun nameOf(code: String, locale: Locale): String = Locale("", code).getDisplayCountry(locale)
}
