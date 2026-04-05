package com.mobilesecurity.scanner.data.network.dto

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class GithubRelease(
    @Json(name = "tag_name") val tagName: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "body") val body: String = "",
    @Json(name = "html_url") val htmlUrl: String = "",
    @Json(name = "published_at") val publishedAt: String = "",
    @Json(name = "assets") val assets: List<GithubAsset> = emptyList()
)

@JsonClass(generateAdapter = true)
data class GithubAsset(
    @Json(name = "name") val name: String = "",
    @Json(name = "browser_download_url") val browserDownloadUrl: String = "",
    @Json(name = "size") val size: Long = 0L,
    @Json(name = "content_type") val contentType: String = ""
)
