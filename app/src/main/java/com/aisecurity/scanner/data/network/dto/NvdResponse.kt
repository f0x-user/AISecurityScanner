package com.aisecurity.scanner.data.network.dto

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class NvdResponse(
    @Json(name = "resultsPerPage") val resultsPerPage: Int = 0,
    @Json(name = "startIndex") val startIndex: Int = 0,
    @Json(name = "totalResults") val totalResults: Int = 0,
    @Json(name = "vulnerabilities") val vulnerabilities: List<NvdVulnerabilityWrapper> = emptyList()
)

@JsonClass(generateAdapter = true)
data class NvdVulnerabilityWrapper(
    @Json(name = "cve") val cve: NvdCve
)

@JsonClass(generateAdapter = true)
data class NvdCve(
    @Json(name = "id") val id: String,
    @Json(name = "published") val published: String = "",
    @Json(name = "lastModified") val lastModified: String = "",
    @Json(name = "vulnStatus") val vulnStatus: String = "",
    @Json(name = "descriptions") val descriptions: List<NvdDescription> = emptyList(),
    @Json(name = "metrics") val metrics: NvdMetrics? = null,
    @Json(name = "references") val references: List<NvdReference> = emptyList()
)

@JsonClass(generateAdapter = true)
data class NvdDescription(
    @Json(name = "lang") val lang: String,
    @Json(name = "value") val value: String
)

@JsonClass(generateAdapter = true)
data class NvdMetrics(
    @Json(name = "cvssMetricV31") val cvssV31: List<NvdCvssMetric> = emptyList(),
    @Json(name = "cvssMetricV30") val cvssV30: List<NvdCvssMetric> = emptyList()
)

@JsonClass(generateAdapter = true)
data class NvdCvssMetric(
    @Json(name = "source") val source: String = "",
    @Json(name = "type") val type: String = "",
    @Json(name = "cvssData") val cvssData: NvdCvssData
)

@JsonClass(generateAdapter = true)
data class NvdCvssData(
    @Json(name = "version") val version: String = "",
    @Json(name = "vectorString") val vectorString: String = "",
    @Json(name = "baseScore") val baseScore: Double = 0.0,
    @Json(name = "baseSeverity") val baseSeverity: String = ""
)

@JsonClass(generateAdapter = true)
data class NvdReference(
    @Json(name = "url") val url: String,
    @Json(name = "source") val source: String = ""
)
