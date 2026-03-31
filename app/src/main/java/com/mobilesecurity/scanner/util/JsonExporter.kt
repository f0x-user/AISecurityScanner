package com.mobilesecurity.scanner.util

import android.content.Context
import com.mobilesecurity.scanner.domain.model.ScanResult
import com.squareup.moshi.JsonWriter
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okio.buffer
import okio.sink
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class JsonExporter @Inject constructor(
    @ApplicationContext private val context: Context
) {
    suspend fun export(scanResult: ScanResult): File = withContext(Dispatchers.IO) {
        val file = File(context.cacheDir, "security_scan_${scanResult.timestamp.epochSecond}.json")
        file.sink().buffer().use { sink ->
            val writer = JsonWriter.of(sink)
            writer.indent = "  "
            writer.beginObject()

            writer.name("id").value(scanResult.id)
            writer.name("timestamp").value(scanResult.timestamp.toString())
            writer.name("overallScore").value(scanResult.overallScore)
            writer.name("durationMs").value(scanResult.durationMs)

            writer.name("summary").beginObject()
            writer.name("critical").value(scanResult.criticalCount)
            writer.name("high").value(scanResult.highCount)
            writer.name("medium").value(scanResult.mediumCount)
            writer.name("low").value(scanResult.lowCount)
            writer.name("zeroDay").value(scanResult.zeroDayCount)
            writer.name("activelyExploited").value(scanResult.activelyExploitedCount)
            writer.endObject()

            writer.name("vulnerabilities").beginArray()
            for (vuln in scanResult.vulnerabilities) {
                writer.beginObject()
                writer.name("id").value(vuln.id)
                writer.name("title").value(vuln.title)
                writer.name("severity").value(vuln.severity.name)
                writer.name("cvssScore").value(vuln.cvssScore)
                writer.name("affectedComponent").value(vuln.affectedComponent)
                writer.name("description").value(vuln.description)
                writer.name("impact").value(vuln.impact)
                writer.name("isZeroDay").value(vuln.isZeroDay)
                writer.name("isActivelyExploited").value(vuln.isActivelyExploited)
                writer.name("detectedAt").value(vuln.detectedAt.toString())
                writer.name("remediationSteps").beginArray()
                vuln.remediation.steps.forEach { writer.value(it) }
                writer.endArray()
                writer.name("cveLinks").beginArray()
                vuln.cveLinks.forEach { writer.value(it) }
                writer.endArray()
                writer.name("affectedApps").beginArray()
                vuln.affectedApps.forEach { writer.value(it) }
                writer.endArray()
                writer.endObject()
            }
            writer.endArray()

            writer.endObject()
            writer.flush()
        }
        file
    }
}
