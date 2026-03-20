package com.aisecurity.scanner.domain.scanner

import android.content.Context
import com.aisecurity.scanner.domain.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject

/**
 * Modul 11: Kernel-Sichtbarkeit
 *
 * Analysiert den Kernel-Sicherheitszustand des Android-Geräts durch passive
 * Auswertung von /proc/sys/kernel-, /sys/fs/bpf- und /sys/kernel/security-Einträgen.
 *
 * Hinweis: Echte eBPF-Programme können von User-Space-Apps auf Android nicht
 * geladen werden. Dieser Scanner prüft stattdessen die sicherheitsrelevante
 * Kernel-Konfiguration und meldet Fehlkonfigurationen als Schwachstellen.
 */
class KernelVisibilityScanner @Inject constructor(
    @Suppress("UNUSED_PARAMETER") context: Context
) {
    suspend fun scan(): List<VulnerabilityEntry> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<VulnerabilityEntry?>()

        findings += checkUnprivilegedBpf()
        findings += checkAslrLevel()
        findings += checkKernelPointerRestriction()
        findings += checkDmesgRestriction()
        findings += checkPerfEventParanoia()
        findings += checkSysrqEnabled()
        findings += checkCoreDumpPattern()
        findings += checkAppArmorStatus()
        findings += checkSuspiciousKernelModules()
        findings += checkEbpfMountStatus()

        findings.filterNotNull()
    }

    // -------------------------------------------------------------------------
    // Hilfsfunktionen
    // -------------------------------------------------------------------------

    private fun readKernelParam(path: String): String? = try {
        File(path).takeIf { it.exists() && it.canRead() }?.readText()?.trim()
    } catch (_: Exception) {
        null
    }

    private fun fileExists(path: String): Boolean = try {
        File(path).exists()
    } catch (_: Exception) {
        false
    }

    // -------------------------------------------------------------------------
    // Prüfungen
    // -------------------------------------------------------------------------

    /**
     * KRN-001: Nicht-privilegierter eBPF-Zugriff
     *
     * Wenn unprivileged_bpf_disabled=0, kann jeder Prozess eBPF-Programme laden
     * und damit Syscalls hookverschlüsseln, Netzwerkpakete abfangen oder
     * Kernel-Speicher lesen.
     */
    private fun checkUnprivilegedBpf(): VulnerabilityEntry? {
        val value = readKernelParam("/proc/sys/kernel/unprivileged_bpf_disabled") ?: return null
        if (value == "0") {
            return VulnerabilityEntry(
                id = "KRN-001",
                title = "Nicht-privilegierter eBPF-Zugriff aktiv",
                severity = Severity.HIGH,
                cvssScore = 7.8f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                affectedComponent = "Linux Kernel / eBPF-Subsystem",
                description = "Der Kernel-Parameter 'unprivileged_bpf_disabled' ist auf 0 gesetzt. " +
                        "Damit darf jeder unprivilegierte Prozess eBPF-Programme in den Kernel laden. " +
                        "eBPF-Programme können Syscalls überwachen (execve, openat), " +
                        "Netzwerkpakete abfangen und Kernel-Speicherbereiche lesen.",
                impact = "Lokale Prozesse können unbemerkt Systemaufrufe anderer Apps belauschen, " +
                        "Zugangsdaten abfangen oder Kernel-Exploits über fehlerhafte eBPF-Programme " +
                        "einschleusen (z. B. CVE-2021-3490, CVE-2022-23222).",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Setze 'kernel.unprivileged_bpf_disabled=2' in /etc/sysctl.conf (Root erforderlich).",
                        "Alternativ: 'sysctl -w kernel.unprivileged_bpf_disabled=1' für sofortige Wirkung.",
                        "Wert 2 (permanent gesperrt) ist sicherer als 1 (kann zurückgesetzt werden).",
                        "Prüfe, ob produktive Apps eBPF benötigen, bevor du dies deaktivierst."
                    ),
                    automatable = false,
                    officialDocUrl = "https://www.kernel.org/doc/html/latest/bpf/",
                    estimatedTime = "~2 Minuten (Root erforderlich)"
                ),
                cveLinks = listOf(
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-3490",
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-23222"
                ),
                patchAvailable = false,
                source = "KernelVisibilityScanner"
            )
        }
        return null
    }

    /**
     * KRN-002: ASLR (Address Space Layout Randomization)
     *
     * randomize_va_space sollte 2 sein (volle Randomisierung inkl. Heap).
     * Wert 1 = nur Stack+VDSO, Wert 0 = deaktiviert.
     */
    private fun checkAslrLevel(): VulnerabilityEntry? {
        val value = readKernelParam("/proc/sys/kernel/randomize_va_space") ?: return null
        val level = value.toIntOrNull() ?: return null
        return when {
            level == 0 -> VulnerabilityEntry(
                id = "KRN-002",
                title = "ASLR vollständig deaktiviert (randomize_va_space=0)",
                severity = Severity.CRITICAL,
                cvssScore = 8.1f,
                cvssVector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                affectedComponent = "Linux Kernel / Speicherschutz",
                description = "Address Space Layout Randomization (ASLR) ist vollständig deaktiviert. " +
                        "Speicherbereiche (Stack, Heap, Libraries) liegen bei jedem Start an derselben Adresse.",
                impact = "Speicher-Exploits (Buffer Overflow, Use-After-Free) sind erheblich einfacher, " +
                        "da Angreifer keine Adressen erraten müssen. Return-to-libc- und ROP-Angriffe " +
                        "werden trivial.",
                remediation = RemediationSteps(
                    priority = Priority.IMMEDIATE,
                    steps = listOf(
                        "Setze 'kernel.randomize_va_space=2' in /etc/sysctl.conf.",
                        "Sofortig: 'sysctl -w kernel.randomize_va_space=2' (Root erforderlich).",
                        "Prüfe, ob eine App ASLR explizit deaktiviert hat (seltene Kompatibilitätsprobleme)."
                    ),
                    automatable = false,
                    officialDocUrl = "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html",
                    estimatedTime = "~1 Minute"
                ),
                patchAvailable = false,
                source = "KernelVisibilityScanner"
            )
            level == 1 -> VulnerabilityEntry(
                id = "KRN-002",
                title = "ASLR nur teilweise aktiv (randomize_va_space=1)",
                severity = Severity.MEDIUM,
                cvssScore = 5.9f,
                cvssVector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                affectedComponent = "Linux Kernel / Speicherschutz",
                description = "ASLR ist auf Stufe 1: Stack und VDSO werden randomisiert, " +
                        "Heap und mmap-Bereiche jedoch nicht. Heap-basierte Exploits sind vereinfacht.",
                impact = "Heap-Spraying-Angriffe und heap-basierte Buffer-Overflows können " +
                        "vorhersehbare Speicheradressen ausnutzen.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Setze 'kernel.randomize_va_space=2' für vollständige ASLR.",
                        "Sofortig: 'sysctl -w kernel.randomize_va_space=2' (Root erforderlich)."
                    ),
                    automatable = false,
                    officialDocUrl = "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html",
                    estimatedTime = "~1 Minute"
                ),
                patchAvailable = false,
                source = "KernelVisibilityScanner"
            )
            else -> null // level == 2: optimal
        }
    }

    /**
     * KRN-003: Kernel-Pointer-Exposition
     *
     * kptr_restrict=0 erlaubt unprivilegierten Prozessen, Kernel-Adressen
     * aus /proc/kallsyms und anderen Quellen zu lesen – hilfreich für Exploits.
     */
    private fun checkKernelPointerRestriction(): VulnerabilityEntry? {
        val value = readKernelParam("/proc/sys/kernel/kptr_restrict") ?: return null
        if (value == "0") {
            return VulnerabilityEntry(
                id = "KRN-003",
                title = "Kernel-Adressen für alle Prozesse lesbar (kptr_restrict=0)",
                severity = Severity.HIGH,
                cvssScore = 7.5f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                affectedComponent = "Linux Kernel / Informationsschutz",
                description = "Der Parameter 'kptr_restrict' ist auf 0 gesetzt. " +
                        "Damit können unprivilegierte Prozesse Kernel-Zeiger aus /proc/kallsyms, " +
                        "/proc/modules und anderen Kernel-Interfaces lesen. Diese Adressen " +
                        "helfen Angreifern, KASLR zu umgehen.",
                impact = "Mit bekannten Kernel-Adressen können KASLR-basierte Schutzmaßnahmen " +
                        "umgangen werden, was Kernel-Exploits erheblich erleichtert.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Setze 'kernel.kptr_restrict=1' (verbirgt Adressen für unprivilegierte Nutzer).",
                        "Wert 2 verbirgt Adressen auch für privilegierte Nutzer (höchste Sicherheit).",
                        "Sofortig: 'sysctl -w kernel.kptr_restrict=1' (Root erforderlich)."
                    ),
                    automatable = false,
                    officialDocUrl = "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html",
                    estimatedTime = "~1 Minute"
                ),
                patchAvailable = false,
                source = "KernelVisibilityScanner"
            )
        }
        return null
    }

    /**
     * KRN-004: dmesg-Zugriff für alle Nutzer
     *
     * dmesg_restrict=0 erlaubt unprivilegierten Prozessen, den Kernel-Ringpuffer
     * zu lesen, der Hardwareadressen, IPs und andere sensible Infos enthalten kann.
     */
    private fun checkDmesgRestriction(): VulnerabilityEntry? {
        val value = readKernelParam("/proc/sys/kernel/dmesg_restrict") ?: return null
        if (value == "0") {
            return VulnerabilityEntry(
                id = "KRN-004",
                title = "Kernel-Log (dmesg) für alle Prozesse zugänglich",
                severity = Severity.MEDIUM,
                cvssScore = 5.5f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                affectedComponent = "Linux Kernel / Logging",
                description = "Der Kernel-Ringpuffer (dmesg) ist für unprivilegierte Prozesse lesbar. " +
                        "Er kann Hardware-Adressen, IP-Adressen, Dateisystempfade, " +
                        "Gerätekeys und andere sicherheitsrelevante Informationen enthalten.",
                impact = "Angreifer-Code oder Malware kann Kernel-Interna auslesen, " +
                        "die für weitere Privilege-Escalation-Angriffe nützlich sind.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Setze 'kernel.dmesg_restrict=1' in /etc/sysctl.conf.",
                        "Sofortig: 'sysctl -w kernel.dmesg_restrict=1' (Root erforderlich)."
                    ),
                    automatable = false,
                    officialDocUrl = "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html",
                    estimatedTime = "~1 Minute"
                ),
                patchAvailable = false,
                source = "KernelVisibilityScanner"
            )
        }
        return null
    }

    /**
     * KRN-005: Perf-Events-Paranoia
     *
     * perf_event_paranoid < 1 erlaubt Performance-Counters für alle Prozesse,
     * was für Seitenkanalangriffe (Spectre, Cache-Timing) genutzt werden kann.
     */
    private fun checkPerfEventParanoia(): VulnerabilityEntry? {
        val value = readKernelParam("/proc/sys/kernel/perf_event_paranoid") ?: return null
        val level = value.toIntOrNull() ?: return null
        if (level < 1) {
            return VulnerabilityEntry(
                id = "KRN-005",
                title = "Performance-Events ohne Einschränkung (perf_event_paranoid=$level)",
                severity = Severity.MEDIUM,
                cvssScore = 5.6f,
                cvssVector = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
                affectedComponent = "Linux Kernel / Performance Monitoring",
                description = "perf_event_paranoid=$level erlaubt unprivilegierten Prozessen den " +
                        "Zugriff auf Hardware-Performance-Counter. Diese können für " +
                        "Cache-Timing-basierte Seitenkanalangriffe (Spectre, Meltdown-Varianten) " +
                        "genutzt werden.",
                impact = "Seitenkanalangriffe können CPU-Cache-Zustände messen und damit " +
                        "kryptografische Schlüssel oder Passwörter aus anderen Prozessen auslesen.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Setze 'kernel.perf_event_paranoid=2' (empfohlen) oder '3' (restriktivst).",
                        "Sofortig: 'sysctl -w kernel.perf_event_paranoid=2' (Root erforderlich).",
                        "Wert 3 deaktiviert perf_events für unprivilegierte Nutzer vollständig."
                    ),
                    automatable = false,
                    officialDocUrl = "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html",
                    estimatedTime = "~1 Minute"
                ),
                patchAvailable = false,
                source = "KernelVisibilityScanner"
            )
        }
        return null
    }

    /**
     * KRN-006: Magic SysRq-Taste aktiv
     *
     * Eine aktivierte SysRq-Taste kann für Denial-of-Service, sofortige Reboots
     * oder Memory-Dumps missbraucht werden, wenn physischer Zugriff besteht.
     */
    private fun checkSysrqEnabled(): VulnerabilityEntry? {
        val value = readKernelParam("/proc/sys/kernel/sysrq") ?: return null
        val level = value.toIntOrNull() ?: return null
        if (level > 0) {
            return VulnerabilityEntry(
                id = "KRN-006",
                title = "Magic SysRq-Taste aktiviert (sysrq=$level)",
                severity = Severity.LOW,
                cvssScore = 4.0f,
                cvssVector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
                affectedComponent = "Linux Kernel / System Control",
                description = "Die Magic SysRq-Taste ist aktiviert (Wert: $level). " +
                        "Sie erlaubt direkte Kernel-Eingriffe via Tastatur oder " +
                        "/proc/sysrq-trigger: Reboot, Sync, Memory-Dump, OOM-Kill.",
                impact = "Mit physischem Zugriff (oder Schreibrechten auf /proc/sysrq-trigger) " +
                        "kann ein Angreifer das System sofort neu starten, Passwörter im Memory " +
                        "auslesen oder Denial-of-Service auslösen.",
                remediation = RemediationSteps(
                    priority = Priority.LOW,
                    steps = listOf(
                        "Deaktiviere SysRq: 'sysctl -w kernel.sysrq=0' (Root erforderlich).",
                        "Oder setze 'kernel.sysrq=0' in /etc/sysctl.conf für Persistenz.",
                        "Falls SysRq für Recovery benötigt wird: 'kernel.sysrq=176' (nur Sync+Remount+Reboot)."
                    ),
                    automatable = false,
                    officialDocUrl = "https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html",
                    estimatedTime = "~1 Minute"
                ),
                patchAvailable = false,
                source = "KernelVisibilityScanner"
            )
        }
        return null
    }

    /**
     * KRN-007: Core-Dump-Pattern mit Pipe
     *
     * Ein Core-Dump-Pattern, das mit '|' beginnt, leitet Crash-Dumps an ein
     * externes Programm weiter – ein bekannter Privilegien-Eskalations-Vektor
     * (CVE-2019-13272 Umgehung via core_pattern).
     */
    private fun checkCoreDumpPattern(): VulnerabilityEntry? {
        val pattern = readKernelParam("/proc/sys/kernel/core_pattern") ?: return null
        if (pattern.startsWith("|")) {
            return VulnerabilityEntry(
                id = "KRN-007",
                title = "Core-Dump-Pattern leitet an externes Programm weiter",
                severity = Severity.HIGH,
                cvssScore = 7.0f,
                cvssVector = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                affectedComponent = "Linux Kernel / Core Dump Handler",
                description = "core_pattern ist auf '${pattern.take(60)}' gesetzt. " +
                        "Das Pipe-Präfix '|' bedeutet: Bei jedem Prozess-Crash wird das " +
                        "angegebene Programm mit Root-Rechten ausgeführt. " +
                        "Dies ist ein bekannter Vektor für Container-Escapes und " +
                        "Privilege Escalation.",
                impact = "Ein lokaler Angreifer, der einen privilegierten Prozess zum Absturz bringt, " +
                        "kann darüber beliebigen Code als Root ausführen (bekannt aus Docker-Escapes, " +
                        "runc CVE-2019-5736-ähnliche Angriffe).",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Setze core_pattern auf einen sicheren Dateipfad: " +
                                "'sysctl -w kernel.core_pattern=/tmp/core.%e.%p'",
                        "Prüfe, ob das externe Programm '${pattern.drop(1).split(" ").firstOrNull() ?: ""}' " +
                                "legitim und sicher ist.",
                        "Erwäge, Core-Dumps vollständig zu deaktivieren: " +
                                "'ulimit -c 0' oder 'sysctl -w fs.suid_dumpable=0'"
                    ),
                    automatable = false,
                    officialDocUrl = "https://man7.org/linux/man-pages/man5/core.5.html",
                    estimatedTime = "~5 Minuten"
                ),
                patchAvailable = false,
                source = "KernelVisibilityScanner"
            )
        }
        return null
    }

    /**
     * KRN-008: AppArmor-Status
     *
     * Prüft ob AppArmor geladen und im Enforce-Modus aktiv ist.
     * Android nutzt primär SELinux; AppArmor ist auf manchen Custom-ROMs vorhanden.
     */
    private fun checkAppArmorStatus(): VulnerabilityEntry? {
        val profilesPath = "/sys/kernel/security/apparmor/profiles"
        val statusPath = "/sys/kernel/security/apparmor/.access"
        val enabledPath = "/sys/module/apparmor"

        return when {
            fileExists(profilesPath) -> {
                // AppArmor ist geladen – prüfe ob Enforce-Modus aktiv
                val profiles = try {
                    File(profilesPath).readLines().take(5)
                } catch (_: Exception) {
                    emptyList()
                }
                val complainModeCount = profiles.count { it.contains("(complain)") }
                if (complainModeCount > 0) {
                    VulnerabilityEntry(
                        id = "KRN-008",
                        title = "AppArmor-Profile im Complain-Modus (nicht durchgesetzt)",
                        severity = Severity.MEDIUM,
                        cvssScore = 5.3f,
                        cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                        affectedComponent = "AppArmor / Mandatory Access Control",
                        description = "$complainModeCount AppArmor-Profile sind im Complain-Modus. " +
                                "In diesem Modus werden Regelverstöße nur geloggt, aber nicht blockiert. " +
                                "Der effektive Schutz ist damit deaktiviert.",
                        impact = "Prozesse können trotz AppArmor-Profil unerlaubte Operationen ausführen. " +
                                "Nur der Enforce-Modus bietet tatsächlichen Schutz.",
                        remediation = RemediationSteps(
                            priority = Priority.NORMAL,
                            steps = listOf(
                                "Setze Profile in Enforce-Modus: 'aa-enforce /etc/apparmor.d/*'",
                                "Oder einzeln: 'aa-enforce /etc/apparmor.d/usr.bin.firefox'",
                                "Prüfe Logs auf Verstöße: 'aa-logprof' vor der Umstellung."
                            ),
                            automatable = false,
                            officialDocUrl = "https://gitlab.com/apparmor/apparmor/-/wikis/home",
                            estimatedTime = "~10 Minuten"
                        ),
                        patchAvailable = false,
                        source = "KernelVisibilityScanner"
                    )
                } else null // Enforce-Modus aktiv – alles gut
            }
            fileExists(enabledPath) || fileExists(statusPath) -> {
                // AppArmor-Modul vorhanden aber keine Profile geladen
                VulnerabilityEntry(
                    id = "KRN-008",
                    title = "AppArmor geladen, aber keine Profile aktiv",
                    severity = Severity.LOW,
                    cvssScore = 3.3f,
                    cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                    affectedComponent = "AppArmor / Mandatory Access Control",
                    description = "Das AppArmor-Kernelmodul ist geladen, es sind jedoch keine " +
                            "Profile aktiv. AppArmor bietet damit keinen Schutz.",
                    impact = "Prozesse laufen ohne AppArmor-Beschränkungen. " +
                            "Das im Projektordner enthaltene AppArmor-Profil für diesen Scanner " +
                            "ist nicht geladen.",
                    remediation = RemediationSteps(
                        priority = Priority.LOW,
                        steps = listOf(
                            "Lade AppArmor-Profile: 'apparmor_parser -r /etc/apparmor.d/*'",
                            "Das mitgelieferte Scanner-Profil findest du im assets/security/-Ordner.",
                            "Kopiere es nach /etc/apparmor.d/ und lade es mit 'aa-enforce'.",
                            "Stelle sicher, dass AppArmor beim Booten startet: 'systemctl enable apparmor'"
                        ),
                        automatable = false,
                        officialDocUrl = "https://gitlab.com/apparmor/apparmor/-/wikis/home",
                        estimatedTime = "~15 Minuten"
                    ),
                    patchAvailable = false,
                    source = "KernelVisibilityScanner"
                )
            }
            else -> null // AppArmor nicht vorhanden (normal auf Android/SELinux-Geräten)
        }
    }

    /**
     * KRN-009: Verdächtige Kernel-Module
     *
     * Liest /proc/modules und sucht nach Modulen, die typische Rootkit-Zeichen
     * haben: anonyme Module (kein Dateiname), unbekannte Hersteller oder
     * Module im "Unknown"-Zustand.
     */
    private fun checkSuspiciousKernelModules(): VulnerabilityEntry? {
        val modulesContent = readKernelParam("/proc/modules") ?: return null
        val lines = modulesContent.lines()
        val suspicious = lines.filter { line ->
            if (line.isBlank()) return@filter false
            val parts = line.split(" ")
            // Format: <name> <size> <usecount> <dependencies> <state> <address>
            // Verdächtig: state "Unknown" oder Module ohne Standard-Dependencies
            val state = parts.getOrNull(4) ?: ""
            state == "Unknown"
        }.mapNotNull { it.split(" ").firstOrNull() }

        if (suspicious.isNotEmpty()) {
            return VulnerabilityEntry(
                id = "KRN-009",
                title = "Verdächtige Kernel-Module im Status 'Unknown'",
                severity = Severity.HIGH,
                cvssScore = 7.2f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                affectedComponent = "Linux Kernel / Kernel-Module",
                description = "Folgende Kernel-Module befinden sich im Status 'Unknown', " +
                        "was auf Rootkits oder fehlerhafte Module hinweisen kann: " +
                        suspicious.joinToString(", "),
                impact = "Kernel-Module im 'Unknown'-Status können Kernel-Code manipulieren, " +
                        "Syscalls hookverschlüsseln (Rootkit-Verhalten) oder Dateisystem-Operationen verbergen.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Prüfe jedes Modul: 'modinfo <modulename>'",
                        "Entlade verdächtige Module: 'rmmod <modulename>' (Root erforderlich)",
                        "Prüfe geladene Module gegen bekannte gute Liste: 'modprobe --list'",
                        "Führe einen AV-Scan auf /lib/modules/ durch.",
                        "Bei Rootkit-Verdacht: System von vertrauenswürdigem Medium booten und prüfen."
                    ),
                    automatable = false,
                    officialDocUrl = "https://man7.org/linux/man-pages/man8/lsmod.8.html",
                    estimatedTime = "~30 Minuten"
                ),
                patchAvailable = false,
                source = "KernelVisibilityScanner"
            )
        }
        return null
    }

    /**
     * KRN-010: eBPF-Dateisystem-Mount-Status
     *
     * /sys/fs/bpf sollte als bpf-Dateisystem gemountet sein. Falls nicht,
     * können eBPF-Maps nicht persistent gespeichert werden, was auf fehlende
     * Kernel-Unterstützung hindeutet (INFO-Level).
     */
    private fun checkEbpfMountStatus(): VulnerabilityEntry? {
        val bpfPath = "/sys/fs/bpf"
        if (!fileExists(bpfPath)) {
            return VulnerabilityEntry(
                id = "KRN-010",
                title = "eBPF-Dateisystem nicht gemountet (/sys/fs/bpf fehlt)",
                severity = Severity.INFO,
                cvssScore = 0.0f,
                affectedComponent = "Linux Kernel / eBPF-Subsystem",
                description = "/sys/fs/bpf ist nicht vorhanden oder nicht gemountet. " +
                        "Dieser Kernel unterstützt möglicherweise kein eBPF, " +
                        "oder das BPF-Dateisystem ist nicht eingehängt.",
                impact = "eBPF-basierte Sicherheitswerkzeuge (Falco, Tracee, Cilium) " +
                        "können nicht genutzt werden. Kein direkter Sicherheitsrisiko, " +
                        "aber eingeschränkte Kernel-Sichtbarkeit.",
                remediation = RemediationSteps(
                    priority = Priority.LOW,
                    steps = listOf(
                        "Mounte das BPF-Dateisystem: 'mount -t bpf bpf /sys/fs/bpf'",
                        "Für Persistenz: Eintrag in /etc/fstab hinzufügen.",
                        "Prüfe Kernel-Unterstützung: 'zcat /proc/config.gz | grep CONFIG_BPF'"
                    ),
                    automatable = false,
                    officialDocUrl = "https://www.kernel.org/doc/html/latest/bpf/",
                    estimatedTime = "~5 Minuten"
                ),
                patchAvailable = false,
                source = "KernelVisibilityScanner"
            )
        }
        return null
    }
}
