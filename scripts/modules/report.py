#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de generación de informes - JSON, CSV y Markdown.
Convierte los resultados del descubrimiento y threat intelligence en tres formatos:
- JSON: datos completos y estructurados (para reutilización programática)
- CSV: solo lista de subdominios (fácil de importar a Excel)
- Markdown: informe legible para humanos, con tablas y secciones.
"""

import json
import csv
from datetime import datetime
from typing import Dict, List

class ReportGenerator:
    """
    Genera informes en tres formatos: JSON, CSV y Markdown.
    Los archivos se guardan en una carpeta (por defecto 'outputs').
    """

    def __init__(self, output_dir: str = "outputs", dominio: str = None):
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.dominio_slug = dominio.replace('.', '_') if dominio else "unknown"
        import os
        os.makedirs(output_dir, exist_ok=True)

    def to_json(self, data: Dict, filename: str = None) -> str:
        if filename is None:
            filename = f"{self.output_dir}/activos_{self.dominio_slug}_{self.timestamp}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        print(f"[✓] JSON guardado en: {filename}")
        return filename

    def to_csv(self, subdomains: List[str], filename: str = None) -> str:
        if filename is None:
            filename = f"{self.output_dir}/subdominios_{self.dominio_slug}_{self.timestamp}.csv"
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['subdominio', 'fecha_deteccion', 'fuente'])
            for sub in subdomains:
                writer.writerow([sub, self.timestamp, 'crt.sh,dnsdumpster,subfinder'])
        print(f"[✓] CSV guardado en: {filename}")
        return filename

    def to_markdown(self, discovery_data: Dict, threat_data: Dict, filename: str = None) -> str:
        activos_info = discovery_data.get('activos', {})
        if filename is None:
            filename = f"{self.output_dir}/informe_{self.dominio_slug}_{self.timestamp}.md"

        # Contar APIs exitosas/fallidas
        apis_ok = 0
        apis_error = 0
        for key, value in threat_data.items():
            if isinstance(value, dict) and value.get('status') == 'ok':
                apis_ok += 1
            elif isinstance(value, dict) and value.get('status') in ['error', 'no_api_key']:
                apis_error += 1

        md_content = f"""# Informe OSINT - {discovery_data.get('domain', 'N/D')}

**Fecha de generación:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Dominio analizado:** {discovery_data.get('domain', 'N/D')}
**IP resuelta:** {threat_data.get('ip_address', 'N/D')}

---

## Resumen Ejecutivo

| Indicador | Valor |
|-----------|-------|
| Subdominios únicos detectados | {discovery_data.get('total_subdomains', 0)} |
| Tipos de registros DNS consultados | {len(discovery_data.get('dns_records', {}))} |
| APIs consultadas (exitosas/fallidas) | {apis_ok}/{apis_ok + apis_error} |

---

## 📋 Inventario de Subdominios ({discovery_data.get('total_subdomains', 0)})

| # | Subdominio |
|---|------------|
"""
        for i, sub in enumerate(discovery_data.get('subdomains', [])[:40], 1):
            md_content += f"| {i} | `{sub}` |\n"

        # ========== SECCIÓN: VERIFICACIÓN DE ACTIVIDAD ==========
        md_content += f"""
---

## 🟢 Verificación de Actividad de Máquinas

**Metodología:**
1. ICMP (ping) - Envío de Echo Request, espera Echo Reply (ICMP-0)
2. TCP/80 - Si ICMP falla, intento de conexión SYN/SYN+ACK

### Resumen de actividad

| Indicador | Valor |
|-----------|-------|
| Total hosts analizados | {activos_info.get('resumen', {}).get('total_hosts', 0)} |
| Hosts **ACTIVOS** | {activos_info.get('resumen', {}).get('activos', 0)} |
| Hosts NO ACTIVOS | {activos_info.get('resumen', {}).get('no_activos', 0)} |
| Detectados por ICMP | {activos_info.get('resumen', {}).get('detectados_por_icmp', 0)} |
| Detectados por TCP | {activos_info.get('resumen', {}).get('detectados_por_tcp', 0)} |

### Resultados detallados

| Host | Estado | Método de detección |
|------|--------|---------------------|
"""
        for item in activos_info.get('resultados_detallados', []):
            host = item.get('host', 'N/A')
            estado = item.get('estado', 'N/A')
            metodo = item.get('metodo_deteccion', 'N/A')
            if estado == "ACTIVA":
                md_content += f"| `{host}` | ✅ ACTIVA | {metodo} |\n"
            else:
                md_content += f"| `{host}` | ❌ {estado} | {metodo} |\n"

        # ========== SECCIÓN: REGISTROS DNS ==========
        md_content += f"""
---

## 🔍 Registros DNS Detectados

| Tipo | Valores |
|------|---------|
"""
        for record_type, values in discovery_data.get('dns_records', {}).items():
            if values:
                md_content += f"| {record_type} | `{', '.join(values[:5])}` |\n"
            else:
                md_content += f"| {record_type} | *No encontrados* |\n"

        # ========== SECCIÓN: WHOIS ==========
        md_content += f"""
---

## 🏢 Información WHOIS

| Campo | Valor |
|-------|-------|
| Registrador | {discovery_data.get('whois', {}).get('registrar', 'N/D')} |
| Fecha de creación | {discovery_data.get('whois', {}).get('creation_date', 'N/D')} |
| Fecha de expiración | {discovery_data.get('whois', {}).get('expiration_date', 'N/D')} |
| Servidores DNS | {', '.join(discovery_data.get('whois', {}).get('name_servers', []))} |

---

## 📊 Estado de las APIs consultadas

| API | Estado | Motivo |
|-----|--------|--------|
"""
        # Lista de APIs a mostrar (clave en threat_data, nombre legible)
        api_list = [
            ('virustotal', 'VirusTotal'),
            ('shodan', 'Shodan'),
            ('censys', 'Censys'),
            ('alienvault', 'AlienVault OTX'),
            ('ipinfo', 'IPinfo'),
            ('ipdata', 'IPdata'),
            ('hunter', 'Hunter.io'),
            ('netlas', 'Netlas'),
            ('urlscan', 'urlscan.io'),
            ('abuseipdb', 'AbuseIPDB'),
            ('bevigil', 'BeVigil'),
            ('github', 'GitHub'),
            ('gitlab', 'GitLab')
        ]
        for key, name in api_list:
            api_data = threat_data.get(key, {})
            status = api_data.get('status', 'unknown')
            if status == 'ok':
                md_content += f"| {name} | ✅ Éxito | - |\n"
            elif status == 'no_api_key':
                md_content += f"| {name} | ⚠️ Sin clave | Configurar en .env |\n"
            elif status == 'error':
                error_type = api_data.get('error_type', 'unknown')
                message = api_data.get('message', 'Error desconocido')
                if error_type == 'invalid_key':
                    md_content += f"| {name} | ❌ Clave inválida | {message} |\n"
                elif error_type == 'quota_exceeded':
                    md_content += f"| {name} | ❌ Cuota agotada | {message} |\n"
                else:
                    md_content += f"| {name} | ❌ Error | {message[:80]} |\n"
            else:
                md_content += f"| {name} | ❓ Desconocido | - |\n"

        # ========== SECCIÓN: THREAT INTELLIGENCE (detalle por API) ==========
        md_content += f"""

## 🛡️ Threat Intelligence - Detalle por API

### VirusTotal
"""
        vt = threat_data.get('virustotal', {})
        if vt.get('status') == 'ok':
            md_content += f"""
- **Reputación:** {vt.get('reputation', 'N/D')}
- **Estadísticas:** {vt.get('last_analysis_stats', {})}
- **Subdominios adicionales:** {len(vt.get('subdomains', []))}
"""
        else:
            md_content += f"- {vt.get('message', 'No disponible')}\n"

        md_content += f"""
### Shodan
"""
        sh = threat_data.get('shodan', {})
        if sh.get('status') == 'ok':
            md_content += f"""
- **Puertos abiertos:** {sh.get('ports', [])}
- **Vulnerabilidades históricas:** {sh.get('vulnerabilities', [])}
- **Tags:** {sh.get('tags', [])}
"""
        else:
            md_content += f"- {sh.get('message', 'No disponible')}\n"

        md_content += f"""
### AlienVault OTX
"""
        av = threat_data.get('alienvault', {})
        if av.get('status') == 'ok':
            md_content += f"""
- **Pulses relacionados:** {av.get('pulse_count', 0)}
- **Reputación:** {av.get('reputation', 'N/A')}
"""
        else:
            md_content += f"- {av.get('message', 'No disponible')}\n"

        md_content += f"""
### Hunter.io
"""
        hu = threat_data.get('hunter', {})
        if hu.get('status') == 'ok':
            md_content += f"""
- **Correos encontrados:** {hu.get('total_emails', 0)}
"""
            for email in hu.get('emails', [])[:5]:
                md_content += f"  - `{email['value']}`\n"
        else:
            md_content += f"- {hu.get('message', 'No disponible')}\n"

        md_content += f"""
### GitHub y GitLab
"""
        gh = threat_data.get('github', {})
        gl = threat_data.get('gitlab', {})
        if gh.get('status') == 'ok':
            md_content += f"- **GitHub:** {gh.get('total_count', 0)} menciones\n"
        if gl.get('status') == 'ok':
            md_content += f"- **GitLab:** {gl.get('total_count', 0)} proyectos\n"

        # ==================== FINGERPRINTING ====================
        fp = threat_data.get('fingerprinting', {})
        md_content += f"""

## 🧬 Fingerprinting Tecnológico

"""
        if fp.get('status') == 'skipped':
            md_content += "⏩ Análisis de fingerprinting omitido por el usuario.\n"
        elif fp.get('status') == 'error':
            md_content += f"⚠️ **Error:** {fp.get('message', 'Desconocido')}\n"
        elif fp.get('results'):
            md_content += "Las siguientes tecnologías fueron detectadas en los subdominios activos:\n\n"
            md_content += "| URL | Tecnologías detectadas |\n"
            md_content += "|-----|------------------------|\n"

            tecnologias_por_url = {}
            for tech_item in fp.get('results', []):
                url = tech_item.get('url', 'N/A')
                tech_name = tech_item.get('technology', 'N/A')
                version = tech_item.get('version', '')
                if version and version != 'N/A':
                    tech_str = f"{tech_name} {version}".strip()
                else:
                    tech_str = tech_name
                if url not in tecnologias_por_url:
                    tecnologias_por_url[url] = []
                tecnologias_por_url[url].append(tech_str)

            for url, tecnologias in tecnologias_por_url.items():
                tecnologias_unicas = sorted(set(tecnologias))
                techs_str = ", ".join(tecnologias_unicas)
                md_content += f"| `{url[:60]}` | {techs_str} |\n"

            total_tech = fp.get('total_technologies', len(fp.get('results', [])))
            md_content += f"\n*Total de tecnologías detectadas: {total_tech}*\n"
        else:
            md_content += "No se detectaron tecnologías (o no se pudo realizar el análisis).\n"

        # ==================== VULNERABILIDADES ====================
        vuln = threat_data.get('vulnerabilities', {})
        md_content += f"""
        
## 🚨 Vulnerabilidades y Exploits

"""
        if vuln.get('status') == 'skipped':
            md_content += "⏩ Búsqueda de vulnerabilidades omitida por el usuario.\n"
        elif vuln.get('status') == 'error':
            md_content += f"⚠️ **Error:** {vuln.get('message', 'Desconocido')}\n"
        elif vuln.get('results'):
            md_content += "A continuación se listan las vulnerabilidades (CVE) asociadas a las tecnologías detectadas, junto con la disponibilidad de exploits públicos en Exploit-DB.\n\n"
            for tech_item in vuln.get('results', []):
                technology = tech_item.get('technology', 'Desconocida')
                version = tech_item.get('version', '')
                cves = tech_item.get('cves', [])
                if not cves:
                    continue
                md_content += f"#### Tecnología: `{technology} {version}`\n\n"
                md_content += "| CVE | Severidad | Descripción | Exploit público |\n"
                md_content += "|-----|-----------|-------------|----------------|\n"
                for cve in cves:
                    cve_id = cve.get('id', 'N/A')
                    severity = cve.get('severity', 'N/A')
                    description = cve.get('description', '')[:80]
                    exploit_available = "✅ Sí" if cve.get('exploit_available') else "❌ No"
                    md_content += f"| `{cve_id}` | {severity} | {description} | {exploit_available} |\n"
                md_content += "\n"
            total_cves = vuln.get('total_cves', 0)
            total_exploits = vuln.get('total_exploits', 0)
            md_content += f"\n*Total de CVEs encontrados: {total_cves} | Con exploits públicos: {total_exploits}*\n"
        else:
            md_content += "No se encontraron vulnerabilidades asociadas (o no se pudo completar el análisis).\n"

        # ==================== DARK WEB ====================
        md_content += f"""
## 🌑 Monitorización en Dark Web (Tor)

"""
        dw = threat_data.get('darkweb', {})
        if dw.get('status') == 'error':
            md_content += f"⚠️ **Error:** {dw.get('message', 'Desconocido')}\n"
        elif dw.get('status') == 'skipped':
            md_content += "⏩ Búsqueda en Dark Web omitida por el usuario.\n"
        elif dw.get('status') == 'success':
            md_content += f"- **Palabra clave:** `{dw.get('keyword', 'N/A')}`\n"
            md_content += f"- **Enlaces .onion encontrados (búsqueda multi-motor):** {dw.get('total_links_found', 0)}\n\n"
            raw_results = dw.get('raw_results', [])
            if raw_results:
                md_content += "#### 🔎 Resultados de búsqueda (primeros 20)\n\n"
                md_content += "| # | Título | Enlace |\n"
                md_content += "|---|--------|--------|\n"
                for i, r in enumerate(raw_results[:20], 1):
                    title = r.get('title', 'N/A')[:60]
                    link = r.get('link', 'N/A')
                    md_content += f"| {i} | {title} | `{link}` |\n"
            analyzed = dw.get('analyzed_threats', [])
            if analyzed:
                md_content += "\n#### 🚨 Análisis de amenazas por crawling\n\n"
                md_content += "| # | URL | Título | Nivel de amenaza | Correos encontrados |\n"
                md_content += "|---|-----|--------|------------------|---------------------|\n"
                for i, a in enumerate(analyzed, 1):
                    threat_icon = "🔴" if a['threat_level'] == 'HIGH' else "🟠" if a['threat_level'] == 'MEDIUM' else "🟢"
                    emails_str = ", ".join(a.get('emails', [])[:2]) if a.get('emails') else "-"
                    url_short = a['url'][:60] + '...' if len(a['url']) > 60 else a['url']
                    title_short = a['title'][:40] + '...' if len(a['title']) > 40 else a['title']
                    md_content += f"| {i} | `{url_short}` | {title_short} | {threat_icon} {a['threat_level']} | {emails_str} |\n"
            else:
                md_content += "\n*No se pudo realizar el crawling/análisis de enlaces (sin resultados o error).*\n"
        else:
            md_content += "No se realizó búsqueda.\n"

        # ==================== ADVERTENCIAS (todas las APIs con error) ====================
        md_content += """
## ⚠️ Advertencias sobre APIs

"""
        warnings = []
        for api_name, api_result in threat_data.items():
            if isinstance(api_result, dict) and api_result.get('status') == 'error':
                error_type = api_result.get('error_type')
                msg = api_result.get('message', 'Error desconocido')
                if error_type:
                    warnings.append(f"- **{api_name.capitalize()}**: {msg}")
                else:
                    warnings.append(f"- **{api_name.capitalize()}**: {msg}")
        if warnings:
            md_content += "\n".join(warnings) + "\n"
        else:
            md_content += "No se detectaron problemas con las API keys o cuotas.\n"

        # ========== HERRAMIENTAS MANUALES Y LIMITACIONES ==========
        md_content += f"""

---

## 🛠️ Herramientas y APIs Utilizadas

| Categoría | Herramientas/APIs |
|-----------|-------------------|
| Descubrimiento | crt.sh, DNSdumpster, Subfinder, DNS, WHOIS |
| Threat Intel | Shodan, Censys, VirusTotal, AlienVault OTX |
| Geolocalización | IPinfo, IPdata |
| Búsqueda de emails | Hunter.io |
| Activos expuestos | Netlas, urlscan.io |
| Reputación de IP | AbuseIPDB |
| Subdominios | BeVigil |
| Repositorios | GitHub, GitLab |
| Dark Web | osint-darkweb-pkg (multi-motor), Ahmia, crawling propio |
| Fingerprinting | Wappalyzer (wappalyzer-next) |
| Vulnerabilidades | NVD API (nvdlib) |
| Exploits | Exploit-DB (searchsploit o pyxploitdb) |

---

"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(md_content)
        print(f"[✓] Informe Markdown guardado en: {filename}")
        return filename