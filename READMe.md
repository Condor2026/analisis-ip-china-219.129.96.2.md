# Análisis CTI: IP China 219.129.96.2 - Campaña Multi-Malware (CardSpy + GandCrab)

> **Tipo de informe:** Análisis de infraestructura maliciosa y campaña asociada  
> **Fecha:** Junio 2026  
> **Autor:** Condor2026  
> **TLP:** CLEAR (información pública)

---

## 📌 Resumen Ejecutivo

La dirección IP `219.129.96.2` (perteneciente a **Chinanet AS4134**, China) ha sido identificada como infraestructura compartida para la distribución de al menos dos familias de malware: **CardSpy** (trojan bancario/spyware) y **GandCrab** (ransomware).
Ambos comparten colecciones en VirusTotal con la IP, indicando una misma campaña o actor de amenaza.

| Métrica | Valor |
|---------|-------|
| **IP** | `219.129.96.2` |
| **Community Score (VT)** | -7 (maliciosa) |
| **Vendors que la marcan** | 9/91 |
| **ASN** | AS4134 (Chinanet) |
| **País** | China |
| **Malware asociado** | CardSpy (56/71), GandCrab (66/72) |
| **APT vinculado (posible)** | Lotus Blossum |

---

## 🧠 Metodología de análisis

La investigación siguió un enfoque de **pivoteo CTI**:

1. **Detección inicial** → Panel Andrómeda (4846 incidentes, puerto 5090)
2. **Selección de IOC** → IP `219.129.96.2` con alta recurrencia
3. **Análisis en VirusTotal** → Exploración de relaciones (graphs, colecciones, archivos comunicantes)
4. **Pivoteo a colecciones** → Identificación de `d3bf06f3... - Bitdefender Renamed Submission Wizard & Lotus Blossum`
5. **Extracción de malware** → CardSpy y GandCrab desde la misma colección
6. **Análisis de comportamiento** → TTPs, detecciones, reglas Sigma e IDS
7. **Generación de IOCs** → IP + hashes

---

## 🦠 Malware identificado

### 1. CardSpy (Trojan bancario / Spyware)

| Campo | Valor |
|-------|-------|
| **SHA256** | `000000f24100cf5d9bf816c89f9bb5f538f5c703a89a6d6c58afb15c00b38fcb` |
| **Nombre** | `ee64448ba271f86de70b9f84fd8d5ef7.virus` |
| **Tamaño** | 183.02 KB |
| **Tipo** | PE executable (Windows) |
| **Detección** | 56/71 |
| **Community Score** | -57 |
| **Etiquetas VT** | `spreader`, `detect-debug-environment`, `corrupt` |
| **Familia** | CardSpy / Graftor / Urelas |
| **Categoría** | Trojan, Spyware |

**Vendors destacados que lo detectan:**
- BitDefender: `Gen:Variant.Graftor.119523`
- ESET-NOD32: `Win32/Spy.CardSpy.NAF Trojan`
- Kaspersky: `HEUR:Trojan.Win32.Wecod.gen`
- Microsoft: `Trojan:Win32/Urelas.JU!MTB`

---

### 2. GandCrab (Ransomware)

| Campo | Valor |
|-------|-------|
| **SHA256** | `00001b7a3fa3486ec2b309d2060cc9f8fc9b3d94163afdedf57e81c11416a2ff` |
| **Nombre** | `p3hngak.exe` |
| **Tamaño** | 303.51 KB |
| **Tipo** | PE executable (Windows) |
| **Detección** | 66/72 |
| **Community Score** | -57 |
| **Etiquetas VT** | `persistence`, `spreader`, `checks-network-adapters`, `runtime-modules`, `overlay`, `direct-cpu-clock-access` |
| **Familia** | GandCrab / Chapak / GandCrypt |
| **Categoría** | Trojan, Ransomware |

**Vendors destacados que lo detectan:**
- BitDefender: `Trojan.GenericKDZ.43689`
- DrWeb: `Trojan.Encoder.24384`
- Kaspersky: `HEUR:Trojan-Ransom.Win32.GandCrypt.gen`
- Microsoft: `Ransom:Win32/Gandcrab.SF!MTB`
- TrendMicro: `Ransom.Win32.GANDCRAB.SMLA.hp`

---

## 🧩 TTPs detectados

### Comportamiento (basado en sandbox y reglas)

| TTP | Descripción | Evidencia |
|-----|-------------|-----------|
| **Persistencia** | Creación de clave RUN en registro | Sigma rule: *New RUN Key Pointing to Suspicious Folder* |
| **Detección de entorno** | Consulta de IP externa | DNS query a `api.ipify.org` (GandCrab) |
| **Domain fronting** | Uso de CDNs legítimos | Comunicación con Akamai, Azure, Microsoft |
| **Ocultamiento** | `detect-debug-environment` | Evita análisis en sandbox |
| **Propagación** | `spreader` | Capacidad de auto-propagar |

### Reglas Sigma detectadas (GandCrab)

| Regla | Severidad |
|-------|-----------|
| New RUN Key Pointing to Suspicious Folder | CRITICAL |
| Suspicious DNS Query for IP Lookup Service APIs | HIGH |
| CurrentVersion Autorun Keys Modification | MEDIUM |

### Reglas IDS/ET Open detectadas

| Regla | Severidad |
|-------|-----------|
| ET MALWARE Observed GandCrab Domain (.bit in DNS Lookup) | HIGH |
| ET INFO External IP Lookup Domain (whatismyipaddress.com) | INFO |

---

## 🔗 Relaciones y pivoteo

### Colecciones compartidas en VirusTotal

La IP `219.129.96.2` aparece en las mismas colecciones que ambos malware:

- `d3bf06f3c6b8cf115f386f853939819f22bb0b9c412ac3696c143ea3440e5bc3 - Bitdefender Renamed Submission Wizard & Lotus Blossum`
- `Government of Alberta - U of A Telus`
- `Alberta NDP`
- `finanse.mf.gov.pl` (Ministerio de Finanzas de Polonia)

Esto sugiere que la infraestructura puede estar siendo utilizada en campañas dirigidas a **entidades gubernamentales de Canadá y Polonia**.

### Contenido en graphs de otros analistas

El hash de GandCrab aparece en **98 graphs públicos** de VirusTotal, indicando alta circulación y atención de la comunidad.

---

## 📊 Indicadores de Compromiso (IOCs)

### IP
```
219.129.96.2
```

### Hashes (SHA256)
```
000000f24100cf5d9bf816c89f9bb5f538f5c703a89a6d6c58afb15c00b38fcb  # CardSpy
00001b7a3fa3486ec2b309d2060cc9f8fc9b3d94163afdedf57e81c11416a2ff  # GandCrab
```

### Reglas de detalle recomendadas
- Monitorear tráfico saliente hacia `219.129.96.2`
- Alertar sobre ejecutables que consulten `api.ipify.org` desde procesos no navegador
- Detectar modificaciones en claves RUN apuntando a rutas sospechosas

---

## 🎯 Conclusión y recomendaciones

### Conclusión
La IP `219.129.96.2` actúa como **infraestructura compartida** para al menos dos familias de malware de propósito diferente (spyware bancario + ransomware). La presencia en colecciones con nombres asociados a **Lotus Blossum** (APT atribuido a China) sugiere posible vinculación con un actor patrocinado por un estado, aunque la evidencia no es concluyente.

### Recomendaciones para equipos defensivos

| Acción | Prioridad |
|--------|-----------|
| Bloquear IP `219.129.96.2` a nivel de firewall/IDS | 🔴 ALTA |
| Implementar reglas Sigma para detección de RUN key y DNS a `api.ipify.org` | 🟠 MEDIA |
| Monitorear tráfico hacia CDNs (Akamai, Azure) con inspección DPI | 🟠 MEDIA |
| Añadir ambos hashes a bloqueos de endpoint (EDR/AV) | 🔴 ALTA |

---

## 📎 Anexos

- [VirusTotal - IP 219.129.96.2](https://www.virustotal.com/gui/ip-address/219.129.96.2)
- [VirusTotal - CardSpy hash](https://www.virustotal.com/gui/file/000000f24100cf5d9bf816c89f9bb5f538f5c703a89a6d6c58afb15c00b38fcb)
- [VirusTotal - GandCrab hash](https://www.virustotal.com/gui/file/00001b7a3fa3486ec2b309d2060cc9f8fc9b3d94163afdedf57e81c11416a2ff)

---

*Este informe fue generado como parte de un portafolio personal de Cyber Threat Intelligence (CTI). Para contacto profesional: [Condor2026]*
```

---

## ✅ ESTO INCLUYE:

| Sección | Contenido |
|---------|-----------|
| Resumen ejecutivo | Tabla con métricas clave |
| Metodología | Pasos claros de análisis |
| Malware (2) | Tablas completas con vendors |
| TTPs | Comportamiento + reglas Sigma/IDS |
| Relaciones | Colecciones y APT Lotus Blossum |
| IOCs | IP + hashes |
| Recomendaciones | Priorizadas para equipos defensivos |
| Anexos | Enlaces directos a VT |

---
By Condor2026 SpectrumSecurity
