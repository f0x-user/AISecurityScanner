package com.aisecurity.scanner.data.network.dto

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class CisaKevResponse(
    @Json(name = "title") val title: String = "",
    @Json(name = "catalogVersion") val catalogVersion: String = "",
    @Json(name = "dateReleased") val dateReleased: String = "",
    @Json(name = "count") val count: Int = 0,
    @Json(name = "vulnerabilities") val vulnerabilities: List<CisaKevEntry> = emptyList()
)

@JsonClass(generateAdapter = true)
data class CisaKevEntry(
    @Json(name = "cveID") val cveId: String,
    @Json(name = "vendorProject") val vendorProject: String = "",
    @Json(name = "product") val product: String = "",
    @Json(name = "vulnerabilityName") val vulnerabilityName: String = "",
    @Json(name = "dateAdded") val dateAdded: String = "",
    @Json(name = "shortDescription") val shortDescription: String = "",
    @Json(name = "requiredAction") val requiredAction: String = "",
    @Json(name = "dueDate") val dueDate: String = "",
    @Json(name = "knownRansomwareCampaignUse") val knownRansomwareCampaignUse: String = "Unknown"
)
