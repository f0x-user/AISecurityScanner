package com.aisecurity.scanner.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.aisecurity.scanner.domain.model.Severity
import com.aisecurity.scanner.ui.theme.*

@Composable
fun SeverityBadge(
    severity: Severity,
    modifier: Modifier = Modifier,
    showLabel: Boolean = true
) {
    val (bgColor, textColor, icon, label) = severityVisuals(severity)
    val cdText = "Schweregrad-Symbol: $label"

    Row(
        modifier = modifier
            .clip(RoundedCornerShape(4.dp))
            .background(bgColor)
            .padding(horizontal = 8.dp, vertical = 4.dp)
            .semantics { contentDescription = cdText },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null, // beschrieben durch semantics oben
            tint = textColor,
            modifier = Modifier.size(14.dp)
        )
        if (showLabel) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = textColor
            )
        }
    }
}

data class SeverityVisuals(
    val bgColor: Color,
    val textColor: Color,
    val icon: ImageVector,
    val label: String
)

fun severityVisuals(severity: Severity): SeverityVisuals = when (severity) {
    Severity.CRITICAL -> SeverityVisuals(SeverityCritical, Color.White, Icons.Default.Error, "KRITISCH")
    Severity.HIGH -> SeverityVisuals(SeverityHigh, Color.White, Icons.Default.Warning, "HOCH")
    Severity.MEDIUM -> SeverityVisuals(SeverityMedium, Color.Black, Icons.Default.Info, "MITTEL")
    Severity.LOW -> SeverityVisuals(SeverityLow, Color.White, Icons.Default.CheckCircle, "NIEDRIG")
    Severity.INFO -> SeverityVisuals(SeverityInfo, Color.White, Icons.Default.HelpOutline, "INFO")
}

@Composable
fun ScoreGauge(score: Int, modifier: Modifier = Modifier) {
    val color = when {
        score >= 80 -> ScoreGood
        score >= 50 -> ScoreWarning
        else -> ScoreDanger
    }
    val label = when {
        score >= 80 -> "Gut"
        score >= 50 -> "Mittelmäßig"
        else -> "Kritisch"
    }
    Column(
        modifier = modifier.semantics {
            contentDescription = "Sicherheits-Score-Anzeige: $score von 100"
        },
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = score.toString(),
            style = MaterialTheme.typography.displayMedium,
            color = color
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = color
        )
    }
}
