package com.mobilesecurity.scanner.data.network.dto

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class HibpBreachEntry(
    @Json(name = "Name") val name: String,
    @Json(name = "Title") val title: String,
    @Json(name = "Domain") val domain: String,
    @Json(name = "BreachDate") val breachDate: String,
    @Json(name = "AddedDate") val addedDate: String,
    @Json(name = "ModifiedDate") val modifiedDate: String,
    @Json(name = "PwnCount") val pwnCount: Long,
    @Json(name = "Description") val description: String,
    @Json(name = "DataClasses") val dataClasses: List<String>,
    @Json(name = "IsVerified") val isVerified: Boolean,
    @Json(name = "IsFabricated") val isFabricated: Boolean,
    @Json(name = "IsSensitive") val isSensitive: Boolean,
    @Json(name = "IsRetired") val isRetired: Boolean,
    @Json(name = "IsSpamList") val isSpamList: Boolean,
    @Json(name = "IsMalware") val isMalware: Boolean,
    @Json(name = "IsSubscriptionFree") val isSubscriptionFree: Boolean = false,
    @Json(name = "LogoPath") val logoPath: String = ""
)
