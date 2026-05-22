"""
Módulo de generación de informes - JSON, CSV y Markdown
"""

import json
import csv
from datetime import datetime
from typing import Dict, List

class ReportGenerator:
    def __init__(self, output_dir: str = "outputs"):
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        import os
        os.makedirs(output_dir, exist_ok=True)
    
    def to_json(self, data: Dict, filename: str = None) -> str:
        """Guarda los resultados completos en JSON"""
        if filename is None:
            filename = f"{self.output_dir}/activos_{self.timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"[✓] JSON guardado en: {filename}")
        return filename
    
    def to_csv(self, subdomains: List[str], filename: str = None) -> str:
        """Guarda los subdominios en CSV"""
        if filename is None:
            filename = f"{self.output_dir}/subdominios_{self.timestamp}.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['subdominio', 'fecha_deteccion', 'fuente'])
            for sub in subdomains:
                writer.writerow([sub, self.timestamp, 'crt.sh,dnsdumpster,subfinder'])
        
        print(f"[✓] CSV guardado en: {filename}")
        return filename
    
    def to_markdown(self, discovery_data: Dict, threat_data: Dict, filename: str = None) -> str:
        """Genera un informe completo en Markdown"""
        activos_info = discovery_data.get('activos', {})
        
        if filename is None:
            filename = f"{self.output_dir}/informe_{self.timestamp}.md"
        
        # Extraer estadísticas de APIs
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
**Metodología:** 100% Pasiva / No intrusiva

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
        
        # ========= SECCIÓN DE VERIFICACIÓN DE ACTIVIDAD =========
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
        
        resultados_detallados = activos_info.get('resultados_detallados', [])
        for item in resultados_detallados:
            host = item.get('host', 'N/A')
            estado = item.get('estado', 'N/A')
            metodo = item.get('metodo_deteccion', 'N/A')
            
            if estado == "ACTIVA":
                md_content += f"| `{host}` | ✅ ACTIVA | {metodo} |\n"
            else:
                md_content += f"| `{host}` | ❌ {estado} | {metodo} |\n"
        
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
        
        # ==================== SECCIÓN DARK WEB (NUEVA) ====================
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
            md_content += f"- **Enlaces .onion encontrados:** {dw.get('total', 0)}\n\n"
            if dw.get('results'):
                md_content += "| # | Título | Enlace |\n"
                md_content += "|---|--------|--------|\n"
                for i, r in enumerate(dw['results'][:10], 1):
                    title = r.get('title', 'N/A')[:50]
                    link = r.get('link', 'N/A')
                    md_content += f"| {i} | {title} | `{link}` |\n"
            else:
                md_content += "No se encontraron enlaces .onion para la búsqueda.\n"
        else:
            md_content += "No se realizó búsqueda.\n"
        
        # ========= CONTINUACIÓN INFORME ORIGINAL =========
        md_content += f"""
### Herramientas de uso manual (sin API pública)

- **Wappalyzer:** {threat_data.get('wappalyzer_guide', {}).get('url', 'N/A')}
- **BuiltWith:** {threat_data.get('builtwith_guide', {}).get('url', 'N/A')}

---

## ⚠️ Limitaciones del Análisis

1. **Análisis 100% pasivo** - No se realizaron escaneos activos contra los sistemas de Zunder
2. **Límites de API** - Los planes gratuitos tienen restricciones de rate limiting
3. **Información histórica** - Algunas APIs pueden mostrar datos no actuales
4. **Sin validación activa** - Los servicios pueden no estar operativos actualmente

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
| **Dark Web** | Ahmia (motor .onion) a través de Tor |

---

*Este informe ha sido generado con fines educativos y de auditoría defensiva.
No se ha realizado ninguna interacción no autorizada con los sistemas de Zunder.*
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        print(f"[✓] Informe Markdown guardado en: {filename}")
        return filename