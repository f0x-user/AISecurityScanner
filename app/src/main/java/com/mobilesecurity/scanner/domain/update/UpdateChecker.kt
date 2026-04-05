package com.mobilesecurity.scanner.domain.update

import com.mobilesecurity.scanner.BuildConfig
import com.mobilesecurity.scanner.data.network.GithubApiService
import javax.inject.Inject
import javax.inject.Singleton

sealed class UpdateCheckResult {
    object Checking : UpdateCheckResult()
    object UpToDate : UpdateCheckResult()
    object Dismissed : UpdateCheckResult()
    data class UpdateAvailable(
        val currentVersion: String,
        val latestVersion: String,
        val releaseNotes: String,
        val downloadUrl: String,
        val releasePageUrl: String
    ) : UpdateCheckResult()
    data class Error(val message: String) : UpdateCheckResult()
}

@Singleton
class UpdateChecker @Inject constructor(
    private val githubApiService: GithubApiService
) {
    suspend fun checkForUpdate(): UpdateCheckResult {
        val current = BuildConfig.VERSION_NAME
        val response = runCatching { githubApiService.getLatestRelease() }
            .getOrElse { return UpdateCheckResult.Error(it.message ?: "Netzwerkfehler") }

        if (!response.isSuccessful) return UpdateCheckResult.UpToDate

        val release = response.body() ?: return UpdateCheckResult.UpToDate
        val latest = release.tagName.removePrefix("v").trim()

        return if (isNewerVersion(latest, current)) {
            val apkUrl = release.assets
                .firstOrNull { it.name.endsWith(".apk") }
                ?.browserDownloadUrl
                ?: release.htmlUrl
            UpdateCheckResult.UpdateAvailable(
                currentVersion = current,
                latestVersion = latest,
                releaseNotes = release.body.take(500).ifBlank { "Keine Release-Notizen vorhanden." },
                downloadUrl = apkUrl,
                releasePageUrl = release.htmlUrl
            )
        } else {
            UpdateCheckResult.UpToDate
        }
    }

    private fun isNewerVersion(latest: String, current: String): Boolean {
        val l = latest.split(".").map { it.toIntOrNull() ?: 0 }
        val c = current.split(".").map { it.toIntOrNull() ?: 0 }
        val len = maxOf(l.size, c.size)
        for (i in 0 until len) {
            val lv = l.getOrElse(i) { 0 }
            val cv = c.getOrElse(i) { 0 }
            if (lv > cv) return true
            if (lv < cv) return false
        }
        return false
    }
}
