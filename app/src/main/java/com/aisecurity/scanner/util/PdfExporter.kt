package com.aisecurity.scanner.util

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.pdf.PdfDocument
import com.aisecurity.scanner.domain.model.ScanResult
import com.aisecurity.scanner.domain.model.Severity
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class PdfExporter @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val pageWidth = 595
    private val pageHeight = 842
    private val margin = 40f
    private val lineHeight = 16f

    fun export(scanResult: ScanResult): File {
        val doc = PdfDocument()
        var pageNum = 1
        var y = margin + 20f

        val titlePaint = Paint().apply { isAntiAlias = true; textSize = 18f; isFakeBoldText = true }
        val headingPaint = Paint().apply { isAntiAlias = true; textSize = 14f; isFakeBoldText = true }
        val bodyPaint = Paint().apply { isAntiAlias = true; textSize = 11f }
        val smallPaint = Paint().apply { isAntiAlias = true; textSize = 9f; color = 0xFF666666.toInt() }
        val pageNumPaint = Paint().apply { isAntiAlias = true; textSize = 9f; color = 0xFF888888.toInt() }

        fun newPage(): Pair<PdfDocument.Page, Canvas> {
            val spec = PdfDocument.PageInfo.Builder(pageWidth, pageHeight, pageNum++).create()
            val page = doc.startPage(spec)
            y = margin + 20f
            return page to page.canvas
        }

        fun finishPage(page: PdfDocument.Page, canvas: Canvas) {
            val pageLabel = "Seite ${pageNum - 1}"
            canvas.drawText(pageLabel, (pageWidth - pageNumPaint.measureText(pageLabel) - margin), (pageHeight - margin / 2), pageNumPaint)
            doc.finishPage(page)
        }

        fun checkPageBreak(canvas: Canvas, page: PdfDocument.Page, needed: Float = lineHeight * 3): Pair<PdfDocument.Page, Canvas> {
            return if (y + needed > pageHeight - margin) {
                finishPage(page, canvas)
                newPage()
            } else page to canvas
        }

        fun drawText(canvas: Canvas, text: String, paint: Paint, x: Float = margin) {
            // Wrap long lines
            val maxWidth = pageWidth - margin * 2
            val words = text.split(" ")
            val sb = StringBuilder()
            for (word in words) {
                val test = if (sb.isEmpty()) word else "$sb $word"
                if (paint.measureText(test) > maxWidth) {
                    canvas.drawText(sb.toString(), x, y, paint)
                    y += lineHeight
                    sb.clear()
                    sb.append(word)
                } else {
                    sb.clear()
                    sb.append(test)
                }
            }
            if (sb.isNotEmpty()) {
                canvas.drawText(sb.toString(), x, y, paint)
                y += lineHeight
            }
        }

        val formatter = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm")
            .withZone(ZoneId.systemDefault())

        var (currentPage, canvas) = newPage()

        // === Seite 1: Header & Zusammenfassung ===
        canvas.drawText("AI Security Scanner", margin, y, titlePaint)
        y += 24f
        canvas.drawText("Sicherheitsbericht", margin, y, titlePaint)
        y += 30f

        canvas.drawText("Datum: ${formatter.format(scanResult.timestamp)}", margin, y, bodyPaint)
        y += lineHeight
        canvas.drawText("Scan-Dauer: ${scanResult.durationMs / 1000}s", margin, y, bodyPaint)
        y += lineHeight * 2

        // Score
        val scorePaint = Paint().apply {
            isAntiAlias = true; textSize = 48f; isFakeBoldText = true
            color = when {
                scanResult.overallScore >= 80 -> 0xFF2E7D32.toInt()
                scanResult.overallScore >= 50 -> 0xFFE65100.toInt()
                else -> 0xFFC62828.toInt()
            }
        }
        canvas.drawText("${scanResult.overallScore}/100", margin, y, scorePaint)
        y += 54f
        canvas.drawText("Sicherheits-Score", margin, y, smallPaint)
        y += lineHeight * 2

        // Zusammenfassung
        canvas.drawText("ZUSAMMENFASSUNG", margin, y, headingPaint)
        y += lineHeight + 4f
        listOf(
            "Kritisch" to scanResult.criticalCount,
            "Hoch" to scanResult.highCount,
            "Mittel" to scanResult.mediumCount,
            "Niedrig" to scanResult.lowCount,
            "Zero-Day" to scanResult.zeroDayCount,
            "Aktiv ausgenutzt" to scanResult.activelyExploitedCount
        ).forEach { (label, count) ->
            canvas.drawText("  $label: $count", margin, y, bodyPaint)
            y += lineHeight
        }
        y += lineHeight

        // === Befunde ===
        val sortedVulns = scanResult.vulnerabilities.sortedWith(
            compareBy({ it.severity.order }, { -it.cvssScore })
        )

        if (sortedVulns.isNotEmpty()) {
            val check = checkPageBreak(canvas, currentPage, lineHeight * 4)
            currentPage = check.first; canvas = check.second

            canvas.drawText("BEFUNDE (${sortedVulns.size})", margin, y, headingPaint)
            y += lineHeight + 4f

            for (vuln in sortedVulns) {
                val check2 = checkPageBreak(canvas, currentPage, lineHeight * 8)
                currentPage = check2.first; canvas = check2.second

                // Severity-Label
                val severityColor = when (vuln.severity) {
                    Severity.CRITICAL -> 0xFFB71C1C.toInt()
                    Severity.HIGH -> 0xFFE65100.toInt()
                    Severity.MEDIUM -> 0xFFF57F17.toInt()
                    Severity.LOW -> 0xFF1565C0.toInt()
                    Severity.INFO -> 0xFF37474F.toInt()
                }
                val severityPaint = Paint().apply { isAntiAlias = true; textSize = 10f; color = severityColor; isFakeBoldText = true }
                canvas.drawText("[${vuln.severity.label}]", margin, y, severityPaint)
                drawText(canvas, vuln.title, headingPaint, margin + 60f)
                y += 2f
                canvas.drawText("CVSS: ${vuln.cvssScore} | ${vuln.affectedComponent}", margin, y, smallPaint)
                y += lineHeight

                drawText(canvas, vuln.description, bodyPaint)
                y += 4f

                if (vuln.remediation.steps.isNotEmpty()) {
                    canvas.drawText("Maßnahmen:", margin, y, bodyPaint)
                    y += lineHeight
                    vuln.remediation.steps.take(3).forEachIndexed { i, step ->
                        val check3 = checkPageBreak(canvas, currentPage)
                        currentPage = check3.first; canvas = check3.second
                        drawText(canvas, "  ${i + 1}. $step", smallPaint)
                    }
                }
                y += lineHeight
                canvas.drawLine(margin, y, pageWidth - margin, y, smallPaint)
                y += lineHeight
            }
        }

        finishPage(currentPage, canvas)

        val file = File(context.filesDir, "security_report_${System.currentTimeMillis()}.pdf")
        file.outputStream().use { doc.writeTo(it) }
        doc.close()
        return file
    }
}
