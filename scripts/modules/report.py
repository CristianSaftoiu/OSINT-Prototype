#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de generación de informes - JSON, CSV y Markdown.
Convierte los resultados del descubrimiento y threat intelligence en tres formatos:
- JSON: datos completos y estructurados (para reutilización programática)
- CSV: solo lista de subdominios (fácil de importar a Excel)
- Markdown: informe legible para humanos, con tablas y secciones.
"""

# ==================== IMPORTACIONES ====================
import json          # Para serializar los resultados a JSON
import csv           # Para escribir el archivo CSV de subdominios
from datetime import datetime  # Para obtener la fecha y hora actual (timestamp)
from typing import Dict, List  # Anotaciones de tipos (mejora la legibilidad)

# ==================== CLASE PRINCIPAL ====================
class ReportGenerator:
    """
    Genera informes en tres formatos: JSON, CSV y Markdown.
    Los archivos se guardan en una carpeta (por defecto 'outputs').
    """

    def __init__(self, output_dir: str = "outputs"):
        """
        Constructor.
        :param output_dir: directorio donde se guardarán los informes (se crea si no existe)
        """
        self.output_dir = output_dir
        # Timestamp con formato AAAAMMDD_HHMMSS (ej: 20260526_143022)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        import os
        os.makedirs(output_dir, exist_ok=True)   # Crea el directorio si no existe

    # ------------------------------------------------------------
    # 1. Generar JSON (datos completos)
    # ------------------------------------------------------------
    def to_json(self, data: Dict, filename: str = None) -> str:
        """
        Guarda todos los resultados en un archivo JSON.
        :param data: diccionario con todos los datos (discovery + threat_intel)
        :param filename: nombre del archivo (opcional; si no se da, se genera automático)
        :return: ruta del archivo guardado
        """
        if filename is None:
            filename = f"{self.output_dir}/activos_{self.timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            # json.dump serializa el diccionario a JSON con indentación 2, caracteres UTF-8
            # default=str convierte objetos no serializables (ej. datetime) a string
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"[✓] JSON guardado en: {filename}")
        return filename

    # ------------------------------------------------------------
    # 2. Generar CSV (solo subdominios)
    # ------------------------------------------------------------
    def to_csv(self, subdomains: List[str], filename: str = None) -> str:
        """
        Guarda la lista de subdominios en un archivo CSV.
        :param subdomains: lista de subdominios (strings)
        :param filename: nombre del archivo (opcional)
        :return: ruta del archivo guardado
        """
        if filename is None:
            filename = f"{self.output_dir}/subdominios_{self.timestamp}.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Cabecera
            writer.writerow(['subdominio', 'fecha_deteccion', 'fuente'])
            # Escribir cada subdominio (la fuente es fija, podría mejorarse)
            for sub in subdomains:
                writer.writerow([sub, self.timestamp, 'crt.sh,dnsdumpster,subfinder'])
        
        print(f"[✓] CSV guardado en: {filename}")
        return filename

    # ------------------------------------------------------------
    # 3. Generar informe Markdown (legible)
    # ------------------------------------------------------------
    def to_markdown(self, discovery_data: Dict, threat_data: Dict, filename: str = None) -> str:
        """
        Genera un informe completo en formato Markdown, con tablas y secciones.
        :param discovery_data: resultados de la fase 1 (subdominios, DNS, WHOIS, actividad)
        :param threat_data: resultados de la fase 2 (APIs, dark web)
        :param filename: nombre del archivo (opcional)
        :return: ruta del archivo guardado
        """
        # Extraer la información de verificación de actividad (si existe)
        activos_info = discovery_data.get('activos', {})
        
        if filename is None:
            filename = f"{self.output_dir}/informe_{self.timestamp}.md"
        
        # ========== CONTAR APIS EXITOSAS / FALLIDAS ==========
        apis_ok = 0
        apis_error = 0
        # Recorrer todos los campos de threat_data que son diccionarios y tienen 'status'
        for key, value in threat_data.items():
            if isinstance(value, dict) and value.get('status') == 'ok':
                apis_ok += 1
            elif isinstance(value, dict) and value.get('status') in ['error', 'no_api_key']:
                apis_error += 1
        
        # ========== CABECERA Y RESUMEN EJECUTIVO ==========
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
        
        # Listar subdominios (hasta 40, ordenados alfabéticamente)
        for i, sub in enumerate(discovery_data.get('subdomains', [])[:40], 1):
            md_content += f"| {i} | `{sub}` |\n"
        
        # ========== SECCIÓN: VERIFICACIÓN DE ACTIVIDAD (ICMP / TCP) ==========
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
        
        # Tabla detallada de cada host (dominio y subdominios)
        resultados_detallados = activos_info.get('resultados_detallados', [])
        for item in resultados_detallados:
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
                # Mostrar hasta 5 valores por tipo
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

## 🛡️ Threat Intelligence - Resultados por API

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
        
        # ========== SECCIÓN: DARK WEB ==========
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
            
            # Resultados brutos (primeros 20 enlaces encontrados)
            raw_results = dw.get('raw_results', [])
            if raw_results:
                md_content += "#### 🔎 Resultados de búsqueda (primeros 20)\n\n"
                md_content += "| # | Título | Enlace |\n"
                md_content += "|---|--------|--------|\n"
                for i, r in enumerate(raw_results[:20], 1):
                    title = r.get('title', 'N/A')[:60]
                    link = r.get('link', 'N/A')
                    md_content += f"| {i} | {title} | `{link}` |\n"
            
            # Análisis de amenazas (crawling)
            analyzed = dw.get('analyzed_threats', [])
            if analyzed:
                md_content += "\n#### 🚨 Análisis de amenazas por crawling\n\n"
                md_content += "| # | URL | Título | Nivel de amenaza | Correos encontrados |\n"
                md_content += "|---|-----|--------|------------------|---------------------|\n"
                for i, a in enumerate(analyzed, 1):
                    # Icono según nivel: 🔴 HIGH, 🟠 MEDIUM, 🟢 LOW
                    threat_icon = "🔴" if a['threat_level'] == 'HIGH' else "🟠" if a['threat_level'] == 'MEDIUM' else "🟢"
                    emails_str = ", ".join(a.get('emails', [])[:2]) if a.get('emails') else "-"
                    # Acortar URLs y títulos muy largos
                    url_short = a['url'][:60] + '...' if len(a['url']) > 60 else a['url']
                    title_short = a['title'][:40] + '...' if len(a['title']) > 40 else a['title']
                    md_content += f"| {i} | `{url_short}` | {title_short} | {threat_icon} {a['threat_level']} | {emails_str} |\n"
            else:
                md_content += "\n*No se pudo realizar el crawling/análisis de enlaces (sin resultados o error).*\n"
        else:
            md_content += "No se realizó búsqueda.\n"
        
        # ========== HERRAMIENTAS MANUALES ==========
        md_content += f"""
### Herramientas de uso manual (sin API pública)

- **Wappalyzer:** {threat_data.get('wappalyzer_guide', {}).get('url', 'N/A')}
- **BuiltWith:** {threat_data.get('builtwith_guide', {}).get('url', 'N/A')}

---

## ⚠️ Limitaciones del Análisis

1. **Límites de API** - Los planes gratuitos tienen restricciones de rate limiting
2. **Información histórica** - Algunas APIs pueden mostrar datos no actuales
3. **Dark Web** - La búsqueda depende de la disponibilidad de los motores .onion y de la conectividad a través de Tor.

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

---

"""
        
        # Guardar el contenido Markdown en el archivo
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        print(f"[✓] Informe Markdown guardado en: {filename}")
        return filename