---
title: "RC4-ADAssessment — Häufig gestellte Fragen (FAQ)"
subtitle: "DES/RC4 Kerberos-Verschlüsselungsbewertungstool"
author: "Jan Tiedemann"
date: "April 2026"
---

# RC4-ADAssessment — FAQ

## Allgemein

**F: Was macht dieses Tool?**

Es bewertet die Nutzung von DES- und RC4-Kerberos-Verschlüsselung in Ihrer
Active-Directory-Gesamtstruktur. Es prüft Domain Controller, Vertrauensstellungen,
KRBTGT, Dienstkonten (SPN/gMSA/sMSA/dMSA), KDC-Registrierungsschlüssel,
KDCSVC-Ereignisse (CVE-2026-20833) und Sicherheitsereignisprotokolle (4768/4769)
auf tatsächliche RC4/DES-Ticketnutzung. Jeder Befund enthält kopierbare
PowerShell-Korrekturmaßnahmen.

**F: Warum brauchen wir dieses Tool?**

Microsoft wird RC4 im **Juli 2026** vollständig aus dem Kerberos-KDC-Pfad
entfernen. Nach diesem Datum funktionieren nur noch Konten mit *explizitem* RC4
in `msDS-SupportedEncryptionTypes`. Alles andere wird blockiert. Dieses Tool hilft
Ihnen, alle RC4/DES-Nutzung zu erkennen, Inline-Korrekturmaßnahmen zu erhalten,
den Fortschritt der Bereinigung zu verfolgen und sich auf die Frist vorzubereiten.

**F: Für wen ist dieses Tool gedacht?**

Active-Directory-Administratoren, Sicherheitsteams und Infrastruktur-Ingenieure,
die ihre AD-Umgebungen auf die RC4-Abschaltung vorbereiten müssen.

## Zeitplan & Meilensteine

**F: Was sind die wichtigsten Meilensteine für die RC4-Abschaltung?**

| Datum | Meilenstein |
|-------|-------------|
| Nov 2022 | Vertrauensstellungen und Computer verwenden standardmäßig AES, wenn das Attribut nicht gesetzt ist |
| Jan 2026 | Registrierungsschlüssel `RC4DefaultDisablementPhase` hinzugefügt (CVE-2026-20833) |
| Apr 2026 | Durchsetzungsphase — `DefaultDomainSupportedEncTypes` standardmäßig nur AES |
| Jul 2026 | Vollständige Durchsetzung — Registrierungsschlüssel für RC4-Überschreibung entfernt |

**F: Was passiert nach Juli 2026, wenn wir nicht handeln?**

- Konten, die auf Standard-/Legacy-RC4-Fallback angewiesen sind, werden **blockiert**.
- Konten ohne gesetztes `msDS-SupportedEncryptionTypes` verwenden AES (sicher).
- Konten mit AES in `msDS-SupportedEncryptionTypes` verwenden AES (sicher).
- Konten mit explizitem RC4 (`0x1C`) funktionieren weiterhin als Ausnahmen.

## Voraussetzungen

**F: Welche Berechtigungen werden benötigt?**

Domänen-Administrator oder gleichwertig. Für die Ereignisprotokollanalyse wird die
Mitgliedschaft in der Gruppe „Ereignisprotokollleser" benötigt. Netzwerkzugriff
über WinRM (Port 5985) oder RPC (Port 135) zu den Domain Controllern ist
erforderlich.

**F: Welche PowerShell-Version wird benötigt?**

PowerShell 5.1 oder höher. PowerShell 7+ wird für die parallele
Gesamtstruktur-Überprüfung mit `Invoke-RC4ForestAssessment -Parallel` benötigt.

**F: Welche Module sind Voraussetzung?**

Die Module `ActiveDirectory` und `GroupPolicy` (RSAT-Tools). Installation:

```
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
```

## Scan & Nutzung

**F: Wie lange dauert ein Scan?**

- Schnellscan (nur Konfiguration): ca. 30 Sekunden
- Tiefenscan (alle Benutzer/Computer): ca. 1–2 Minuten
- Vollständiger Scan mit Ereignisprotokollen: ca. 3–5 Minuten

**F: Was ist der Unterschied zwischen Schnellscan und Tiefenscan?**

Der Schnellscan prüft Domain Controller, Vertrauensstellungen, KRBTGT und
Dienstkonten mit SPNs. Der Tiefenscan (`-DeepScan`) überprüft zusätzlich alle
aktivierten Benutzerkonten und alle Computerkonten (außer DCs) auf RC4/DES-
Konfigurationen. Der Tiefenscan enthält KEINE Ereignisprotokollanalyse —
kombinieren Sie ihn mit `-AnalyzeEventLogs` für vollständige Abdeckung.

**F: Kann das Tool eine gesamte Multi-Domain-Gesamtstruktur scannen?**

Ja. `Invoke-RC4ForestAssessment` scannt alle Domänen der Gesamtstruktur.
Optionale Parallelverarbeitung mit `-Parallel -MaxParallelDomains 5` ist unter
PowerShell 7+ verfügbar.

**F: Was sind die drei Hauptbefehle?**

| Befehl | Zweck |
|--------|-------|
| `Invoke-RC4Assessment` | Hauptbewertung für eine einzelne Domäne |
| `Invoke-RC4ForestAssessment` | Gesamtstruktur-Bewertung über alle Domänen |
| `Invoke-RC4AssessmentComparison` | Vergleich zweier JSON-Exporte zur Fortschrittsverfolgung |

**F: Können wir den Fortschritt der Bereinigung verfolgen?**

Ja. Exportieren Sie Ergebnisse als JSON mit `-ExportResults` und vergleichen Sie
dann zwei Durchläufe:

```
Invoke-RC4AssessmentComparison -BaselineFile vorher.json -CurrentFile nachher.json -ShowDetails
```

Der Vergleich umfasst DC-Verschlüsselung, Vertrauensstellungen, Konten,
KDC-Registrierung, KDCSVC-Ereignisse und Ereignisprotokoll-Ticketzähler.

**F: Welche Exportformate sind verfügbar?**

JSON (vollständige Daten) und CSV (Zusammenfassungstabelle), gespeichert im
Ordner `.\Exports\`. Mit `-IncludeGuidance` wird zusätzlich eine
`.txt`-Leitfadendatei generiert.

## Technische Details

**F: Deckt das Tool CVE-2026-20833 ab?**

Ja, vollständig. Das Tool scannt KDCSVC-Systemprotokoll-Ereignisse 201–209, prüft
die `RC4DefaultDisablementPhase`-Registrierungswerte auf allen DCs und bildet alle
Anforderungen des KB-Artikels ab, einschließlich Überwachungsmodus (Wert 1) und
Durchsetzungsmodus (Wert 2).

**F: Ich sehe keine KDCSVC-Events 201–209 auf meinen DCs. Bedeutet das, dass RC4 nicht mehr verwendet wird?**

**Nein.** Das ist ein häufiger Irrtum. Die KDCSVC-Events 201–209 sind ein
**CVE-spezifischer Warnmechanismus**, kein allgemeiner RC4-Scanner. Microsoft
stellt in KB5073381 klar: *„Audit-Ereignisse im Zusammenhang mit dieser Änderung
werden nur erzeugt, wenn Active Directory keine AES-SHA1-Diensttickets oder
Sitzungsschlüssel ausstellen kann. Das Fehlen von Audit-Ereignissen garantiert
nicht, dass alle Nicht-Windows-Geräte die Kerberos-Authentifizierung nach dem
April-Update erfolgreich akzeptieren."*

Viele legitime RC4-Szenarien erzeugen **keine KDCSVC-Events**, darunter:

- Konten ohne gesetztes `msDS-SupportedEncryptionTypes`, die implizit auf RC4
  zurückfallen
- RC4-Sitzungsschlüssel, die in Security-Events 4768/4769 sichtbar sind, aber
  keine KDC-Fallback-Logik auslösen
- Legacy-Dienstkonten mit formal gültiger, aber kryptografisch schwacher
  Konfiguration

Genau deshalb korreliert RC4-ADAssessment mehrere Datenquellen (AD-Attribute,
KDC-Registrierung, KDCSVC-Events *und* Security-Ereignisprotokolle 4768/4769),
anstatt sich auf ein einzelnes Signal zu verlassen. Keine KDCSVC-Events bedeutet
nicht, dass kein RC4 vorhanden ist.

Referenzen:

- [KB5073381 — CVE-2026-20833-Bereitstellungsleitfaden](https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc)
- [RC4-Nutzung in Kerberos erkennen und beheben](https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

**F: Was ist der Unterschied zwischen Kerberos-Tickets und Sitzungsschlüsseln (Session Keys)?**

Kerberos verwendet zwei getrennte kryptografische Ebenen, die jeweils unabhängig
voneinander RC4 oder AES nutzen können:

- **Tickets (TGT und TGS):** Das TGT (Ticket Granting Ticket) wird bei der
  Erstanmeldung (AS-REQ) ausgestellt und mit dem Schlüssel des KRBTGT-Kontos
  verschlüsselt. Das TGS (Dienstticket) wird beim Zugriff auf einen Dienst
  (TGS-REQ) ausgestellt und mit dem Schlüssel des Ziel-Dienstkontos
  verschlüsselt. Der Verschlüsselungstyp des Tickets wird durch das Attribut
  `msDS-SupportedEncryptionTypes` des Zielkontos und die KDC-Konfiguration
  bestimmt. Diesen Wert zeigt das Feld `TicketEncryptionType` in den
  Security-Ereignissen 4768/4769.
- **Sitzungsschlüssel (Session Keys):** Ein temporärer symmetrischer Schlüssel,
  der vom KDC erzeugt und im Ticket hinterlegt wird. Der Sitzungsschlüssel
  verschlüsselt die laufende Kommunikation zwischen Client und Dienst (bzw.
  Client und KDC). Sein Verschlüsselungstyp wird separat ausgehandelt und kann
  sich vom Ticket-Verschlüsselungstyp unterscheiden.

**Warum das für die RC4-Bewertung wichtig ist:** Ein Dienstticket kann
AES-verschlüsselt sein, während der darin enthaltene Sitzungsschlüssel RC4
verwendet — oder umgekehrt. RC4-Sitzungsschlüssel sind eine eigenständige
RC4-Abhängigkeit, die **keine KDCSVC-Events 201–209 auslöst**, da die
Deaktivierungslogik des KDC auf die Ticket-Verschlüsselung abzielt, nicht auf
die Sitzungsschlüssel-Aushandlung. Diese RC4-Sitzungsschlüssel sind nur über
die Security-Ereignisprotokollanalyse (4768/4769) sichtbar — genau deshalb
enthält RC4-ADAssessment die Ereignisprotokoll-Korrelation als kritische
Erkennungsebene.

Referenz:
[MS-KILE — Kerberos Protocol Extensions](https://learn.microsoft.com/openspecs/windows_protocols/ms-kile/2a32282e-6ab7-4f56-b532-870c74e1c653)

**F: Was ist mit dem AzureADKerberos-Objekt in der DC-OU?**

Es wird automatisch erkannt und von den DC-Zählern ausgeschlossen. Das
AzureADKerberos-Objekt ist ein schreibgeschützter Proxy für Entra ID Cloud
Kerberos Trust — es ist kein echter Domain Controller. Ändern Sie seine
Verschlüsselungseinstellungen nicht manuell.

**F: Muss der KDC RC4 aktiviert haben, um RC4-Tickets für Ausnahmekonten auszustellen?**

**Nein.** Der RC4-Codepfad bleibt im KDC auch nach Juli 2026 bestehen. Das Setzen
von `msDS-SupportedEncryptionTypes = 0x1C` auf einem Dienstkonto reicht aus — der
KDC stellt RC4-Tickets nur für dieses spezifische Konto aus, während alle anderen
Konten AES-only bleiben. Eine domänenweite Registrierungsänderung ist nicht
erforderlich.

**F: Welcher Verschlüsselungstyp-Wert wird empfohlen?**

- **24 (0x18)** = AES128 + AES256 — **Empfohlen (nur AES)**
- **28 (0x1C)** = RC4 + AES128 + AES256 — Letzter Ausweg für Legacy-Anwendungen

**F: Wie funktioniert die Erkennung „Fehlende AES-Schlüssel"?**

Konten werden markiert, wenn `msDS-SupportedEncryptionTypes` nicht gesetzt ist
**und** `PasswordLastSet` älter als 5 Jahre ist. Diese Konten haben möglicherweise
nie AES-Schlüssel generiert (da AES-Schlüssel nur erstellt werden, wenn ein
Kennwort gesetzt wird, während die Domänenfunktionsebene 2008 oder höher ist).
Lösung: Kennwort zurücksetzen.

**F: Was erkennt die AES/RC4-Korrelation?**

Konten, die AES in AD *konfiguriert* haben, aber immer noch RC4-Tickets erhalten
(sichtbar in den Ereignisprotokollen). Das bedeutet, dass das Kennwort nach der
AES-Konfiguration nie zurückgesetzt wurde, sodass keine AES-Schlüssel existieren.
Lösung: Kennwort zurücksetzen und Tickets löschen.

**F: Bietet das Tool Korrekturmaßnahmen?**

Ja. Jeder Befund enthält direkt kopierbare PowerShell-Korrekturmaßnahmen. Der
Schalter `-IncludeGuidance` fügt ein vollständiges Referenzhandbuch hinzu, das
Audit-Einrichtung, SIEM-Abfragen, KRBTGT-Rotation und den Juli-2026-Zeitplan
abdeckt.

**F: Muss ich Verschlüsselungstypen auf allen Computerkonten setzen?**

**Nein.** Seit November 2022 tritt der RC4-Fallback für Computer nur auf, wenn das
Attribut des Clients einen Wert ungleich Null hat UND der DC kein AES hat. Wenn
Ihre DCs AES per GPO konfiguriert haben, ist keine Aktion auf normalen
Computerkonten erforderlich.

## Auswirkungen & Nebeneffekte

**F: Was ist mit Linux-Diensten, die Kerberos-Keytabs verwenden?**

Kennwortzurücksetzungen machen bestehende Keytab-Dateien ungültig. Linux-Dienste
(Apache, Nginx, SSSD, Samba, PostgreSQL usw.) müssen ihre Keytabs über `ktpass`
(Windows) oder `ktutil` (Linux) neu generieren. Die `-IncludeGuidance`-Ausgabe
enthält Schritt-für-Schritt-Anleitungen zur Keytab-Neugenerierung.

**F: Was ist der empfohlene Ablauf?**

1. **Entdeckung** — Vollständiger Scan mit Ereignisprotokollen und Export
2. **Bereinigung** — Behebung der kritischsten Probleme mit Inline-Korrekturmaßnahmen
3. **Validierung** — Vergleich von Baseline- und aktueller Bewertung
4. **Tiefenprüfung** — Scan aller Benutzer- und Computerkonten
5. **Abschlussbereiniung** — Kennwortzurücksetzungen für verbleibende Konten
6. **Abschlussvalidierung** — Bestätigung, dass alles bereinigt ist — bereit für Juli 2026

## Installation

**F: Wie installiere ich das Tool?**

```
Install-Module -Name RC4-ADAssessment
Import-Module RC4-ADAssessment
```

**F: Nimmt das Tool Änderungen im Active Directory vor?**

Nein. Das Tool arbeitet ausschließlich **lesend**. Es fragt AD-Attribute,
Registrierungsschlüssel und Ereignisprotokolle ab, ändert aber nichts. Die
Korrekturmaßnahmen werden angezeigt, damit der Administrator sie prüfen und
manuell ausführen kann.
