package com.mobilesecurity.scanner.data.network.dto

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class EmailRepResponse(
    @Json(name = "email") val email: String = "",
    @Json(name = "reputation") val reputation: String = "none",
    @Json(name = "suspicious") val suspicious: Boolean = false,
    @Json(name = "details") val details: EmailRepDetails = EmailRepDetails()
)

@JsonClass(generateAdapter = true)
data class EmailRepDetails(
    @Json(name = "credentials_leaked") val credentialsLeaked: Boolean = false,
    @Json(name = "data_breach") val dataBreach: Boolean = false,
    @Json(name = "blacklisted") val blacklisted: Boolean = false,
    @Json(name = "malicious_activity") val maliciousActivity: Boolean = false
)
