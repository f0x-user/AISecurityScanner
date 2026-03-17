package com.aisecurity.scanner.data.network.dto

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class OsvQueryRequest(
    @Json(name = "version") val version: String? = null,
    @Json(name = "package") val pkg: OsvPackage? = null
)

@JsonClass(generateAdapter = true)
data class OsvPackage(
    @Json(name = "name") val name: String,
    @Json(name = "ecosystem") val ecosystem: String
)

@JsonClass(generateAdapter = true)
data class OsvResponse(
    @Json(name = "vulns") val vulns: List<OsvVuln> = emptyList()
)

@JsonClass(generateAdapter = true)
data class OsvVuln(
    @Json(name = "id") val id: String,
    @Json(name = "summary") val summary: String = "",
    @Json(name = "details") val details: String = "",
    @Json(name = "severity") val severity: List<OsvSeverity> = emptyList(),
    @Json(name = "aliases") val aliases: List<String> = emptyList(),
    @Json(name = "published") val published: String = "",
    @Json(name = "modified") val modified: String = ""
)

@JsonClass(generateAdapter = true)
data class OsvSeverity(
    @Json(name = "type") val type: String,
    @Json(name = "score") val score: String
)
