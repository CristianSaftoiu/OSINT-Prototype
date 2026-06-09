#!/usr/bin/env python3
# ↑ Shebang: indica que este script debe ejecutarse con Python 3

# ============================================================
# DOCUMENTACIÓN INICIAL (docstring)
# ============================================================
"""
Prototipo OSINT - Descubrimiento pasivo de activos + monitorización
Uso: python main.py
Al ejecutar, preguntará el dominio a analizar.
Ejemplo: google.com, microsoft.com
"""

# ==================== IMPORTACIONES ====================
import time          # Para medir el tiempo de ejecución (start_time, elapsed)
import os            # Para acceder a variables de entorno (API keys) y rutas
import re            # Para validar el formato del dominio con expresiones regulares
import platform      # Para detectar SO (útil en mensajes multiplataforma)
from dotenv import load_dotenv  # Función que lee el archivo .env y lo carga en variables de entorno

# ============================================================
# CARGA DE VARIABLES DE ENTORNO
# ============================================================
load_dotenv()         # Busca archivo .env en el directorio actual y carga las variables
print("[DEBUG] Variables de entorno cargadas:", os.getenv('SHODAN_API_KEY') is not None)

# ============================================================
# IMPORTACIÓN DE MÓDULOS PROPIOS (cada uno en scripts/modules/)
# ============================================================
from scripts.modules.discovery import PassiveDiscovery      # Fase 1
from scripts.modules.threat_intel import ThreatIntel        # Fase 2
from scripts.modules.report import ReportGenerator          # Fase 3
from scripts.modules.darkweb_monitor import DarkWebMonitor  # Fase 4

# NUEVO: Módulos para fingerprinting, CVEs y exploits
from scripts.modules.fingerprint import Fingerprinter
from scripts.modules.cve_exploit import CveExploitScanner

# ============================================================
# FUNCIONES AUXILIARES
# ============================================================
def print_banner(dominio):
    """Muestra un banner decorativo con el dominio que se va a analizar."""
    print(f"""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║     PROTOTIPO OSINT - {dominio:<13}                                          ║
    ║     Descubrimiento de activos expuestos                                      ║
    ║     Múltiples APIs: Shodan, Censys, VirusTotal, AlienVault, Hunter, etc.     ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """)

def validar_dominio(dominio):
    """Valida que el dominio tenga un formato correcto usando expresión regular."""
    patron = r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(patron, dominio) is not None

# ============================================================
# FUNCIÓN PRINCIPAL
# ============================================================
def main():
    """Función que orquesta todo el análisis (fases 1 a 4 + fase adicional 2.5 opcional)."""
    
    # --- SOLICITAR DOMINIO AL USUARIO ---
    print("\n" + "="*60)
    print("    PROTOTIPO OSINT - HERRAMIENTA DE RECONOCIMIENTO ")
    print("="*60)
    
    while True:
        dominio = input("   ▶ Introduzca el dominio a analizar (ej: google.com): ").strip().lower()
        if not dominio:
            print("   ⚠️  No ha introducido ningún dominio. Inténtelo de nuevo.\n")
            continue
        if not validar_dominio(dominio):
            print(f"   ⚠️  '{dominio}' no parece un dominio válido. Inténtelo de nuevo.")
            print("      Formato correcto: ejemplo.com, dominio.es, sub.dominio.org\n")
            continue
        print(f"\n   ✅ Dominio aceptado: {dominio}")
        print("   ⏳ Iniciando análisis...\n")
        break
    
    print_banner(dominio)
    start_time = time.time()
    
    # ==================== FASE 1: DESCUBRIMIENTO ====================
    print("\n" + "="*60)
    print("FASE 1 DE 4 - DESCUBRIMIENTO DE ACTIVOS")
    print("="*60)
    
    discovery = PassiveDiscovery(dominio)
    discovery_results = discovery.run_all()
    
    # ==================== FASE 2: THREAT INTELLIGENCE ====================
    print("\n" + "="*60)
    print("FASE 2 DE 4 - THREAT INTELLIGENCE")
    print("="*60)
    
    threat = ThreatIntel(dominio)
    threat_results = threat.run_all()
    
    # ==================== COMBINAR SUBDOMINIOS ====================
    print("\n" + "="*60)
    print("COMBINANDO RESULTADOS DE MÚLTIPLES FUENTES")
    print("="*60)
    
    subdominios_vt = threat_results.get('subdomains_from_virustotal', [])
    subdominios_urlscan = []
    for result in threat_results.get('urlscan', {}).get('results', []):
        domain_found = result.get('domain', '')
        if domain_found and domain_found != dominio and domain_found.endswith(dominio):
            subdominios_urlscan.append(domain_found)
    
    todos_subdominios = set(discovery_results.get('subdomains', []))
    todos_subdominios.update(subdominios_vt)
    todos_subdominios.update(subdominios_urlscan)
    
    discovery_results['subdomains'] = sorted(list(todos_subdominios))
    discovery_results['total_subdomains'] = len(todos_subdominios)
    
    print(f"   [+] Subdominios de crt.sh/Subfinder: {len(discovery_results.get('subdomains', []))}")
    print(f"   [+] Subdominios de VirusTotal: {len(subdominios_vt)}")
    print(f"   [+] Subdominios de urlscan.io: {len(subdominios_urlscan)}")
    print(f"   [+] TOTAL subdominios únicos: {discovery_results['total_subdomains']}")
    
    # ==================== FASE 2.5: FINGERPRINTING + CVEs + EXPLOITS ====================
    print("\n" + "="*60)
    print("FASE 2.5 - ANÁLISIS DE TECNOLOGÍAS, VULNERABILIDADES Y EXPLOITS")
    print("="*60)
    print("   Esta fase detecta tecnologías web (fingerprinting), busca CVEs asociados")
    print("   y comprueba si existen exploits públicos en Exploit-DB.\n")
    
    respuesta_fp = input("   ¿Deseas realizar fingerprinting y búsqueda de vulnerabilidades? (s/n): ").strip().lower()
    if respuesta_fp == 's':
        print("\n   ⏳ Analizando tecnologías y vulnerabilidades...")
        # Obtener lista de URLs solo de subdominios que parecen webs (no wildcards)
        urls = []
        for sub in discovery_results.get('subdomains', []):
            if sub.startswith('*.') or sub == '':
                continue
            urls.append(f"https://{sub}")
        urls = urls[:20]  # Limitar a 20 URLs para no saturar
        
        if not urls:
            print("   ⚠️ No hay subdominios para analizar. Se omitirá la fase.")
        else:
            fp = Fingerprinter()
            tech_results = fp.scan(urls)
            threat_results["fingerprinting"] = tech_results
            print(f"[DEBUG] Tecnologías detectadas: {tech_results.get('total_technologies', 0)}")
            
            cve_scanner = CveExploitScanner()
            vuln_results = cve_scanner.scan(tech_results)
            threat_results["vulnerabilities"] = vuln_results
            print("   ✅ Análisis de vulnerabilidades completado.\n")
    else:
        threat_results["fingerprinting"] = {"status": "skipped"}
        threat_results["vulnerabilities"] = {"status": "skipped"}
        print("   ⏩ Análisis de vulnerabilidades omitido por el usuario.\n")
    
    # ==================== FASE 3: CREAR GENERADOR DE INFORMES (UN SOLO OBJETO) ====================
    print("\n" + "="*60)
    print("FASE 3 DE 4 - GENERANDO INFORMES (JSON, CSV)")
    print("="*60)
    
    # Crear un único generador de informes con el dominio
    reporter = ReportGenerator("outputs", dominio)
    
    # Guardar JSON y CSV (no el Markdown aún, para no duplicar)
    reporter.to_json({
        "dominio_analizado": dominio,
        "discovery": discovery_results,
        "threat_intel": threat_results,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })
    reporter.to_csv(discovery_results.get('subdomains', []))
    
    # ==================== FASE 4: DARK WEB MONITORING ====================
    print("\n" + "="*60)
    print("FASE 4 DE 4 - MONITORIZACIÓN EN DARK WEB (Tor)")
    print("="*60)
    print("   Esta fase busca en la red Tor (dark web) posibles menciones")
    print("   o enlaces relacionados con el dominio.\n")
    
    respuesta_dw = input("   ¿Deseas realizar la búsqueda en la Dark Web? (s/n): ").strip().lower()
    if respuesta_dw == 's':
        print("\n   ⏳ Conectando a la red Tor y realizando la búsqueda...")
        dw = DarkWebMonitor(dominio)
        darkweb_results = dw.run_all()
        threat_results["darkweb"] = darkweb_results
        print("   ✅ Resultados de Dark Web obtenidos.\n")
    else:
        threat_results["darkweb"] = {"status": "skipped"}
        print("   ⏩ Búsqueda en Dark Web omitida por el usuario.\n")
    
    # ==================== AHORA GENERAMOS EL INFORME MARKDOWN (ÚNICO) ====================
    # Una vez que todos los datos están en threat_results, generamos el Markdown final
    print("\n" + "="*60)
    print("GENERANDO INFORME MARKDOWN FINAL")
    print("="*60)
    reporter.to_markdown(discovery_results, threat_results)
    
    # ==================== RESUMEN FINAL (en consola) ====================
    elapsed = time.time() - start_time
    
    print("\n" + "="*60)
    print("RESUMEN DE HALLAZGOS")
    print("="*60)
    
    print(f"\n  📊 ESTADÍSTICAS:")
    print(f"     • Dominio analizado: {dominio}")
    print(f"     • Subdominios únicos detectados: {discovery_results['total_subdomains']}")
    print(f"     • Tipos de registros DNS consultados: {len(discovery_results.get('dns_records', {}))}")
    print(f"     • IP resuelta: {threat_results.get('ip_address', 'N/D')}")
    
    # Verificación de actividad
    activos_info = discovery_results.get('activos', {})
    if activos_info:
        print(f"\n  🟢 VERIFICACIÓN DE ACTIVIDAD:")
        print(f"     • Hosts ACTIVOS: {activos_info.get('resumen', {}).get('activos', 0)}/{activos_info.get('resumen', {}).get('total_hosts', 0)}")
        print(f"     • Detectados por ICMP (ping): {activos_info.get('resumen', {}).get('detectados_por_icmp', 0)}")
        print(f"     • Detectados por TCP/80: {activos_info.get('resumen', {}).get('detectados_por_tcp', 0)}")
    
    # Resumen fingerprinting
    fp_res = threat_results.get("fingerprinting", {})
    if fp_res.get("status") != "skipped" and fp_res.get("status") != "error":
        print(f"\n  🧬 FINGERPRINTING:")
        print(f"     • Tecnologías detectadas: {fp_res.get('total_technologies', 0)}")
        print(f"     • URLs analizadas: {len(fp_res.get('results', []))}")
    if threat_results.get("vulnerabilities", {}).get("status") not in ("skipped", "error"):
        vuln_res = threat_results.get("vulnerabilities", {})
        print(f"\n  🚨 VULNERABILIDADES Y EXPLOITS:")
        print(f"     • CVEs encontrados: {vuln_res.get('total_cves', 0)}")
        print(f"     • Exploits públicos detectados: {vuln_res.get('total_exploits', 0)}")
    
    # Resumen dark web
    dw_res = threat_results.get("darkweb", {})
    if dw_res.get("status") == "success":
        print(f"\n  🌑 DARK WEB:")
        print(f"     • Búsqueda realizada para: {dw_res.get('keyword', 'N/A')}")
        print(f"     • Enlaces .onion encontrados: {dw_res.get('total', 0)}")
    elif dw_res.get("status") == "error":
        print(f"\n  🌑 DARK WEB:")
        print(f"     • Error: {dw_res.get('message', 'Desconocido')}")
    
    print(f"\n  📁 ARCHIVOS GENERADOS:")
    print(f"     • outputs/activos_{dominio.replace('.', '_')}_*.json")
    print(f"     • outputs/subdominios_{dominio.replace('.', '_')}_*.csv")
    print(f"     • outputs/informe_{dominio.replace('.', '_')}_*.md")
    
    print(f"\n  ⏱️  Tiempo total de ejecución: {elapsed:.2f} segundos")
    
    print("\n" + "="*60)
    print("✅ PROTOTIPO EJECUTADO CORRECTAMENTE")
    print("="*60)

# ============================================================
# PUNTO DE ENTRADA
# ============================================================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Ejecución interrumpida por el usuario")
    except Exception as e:
        print(f"\n[!] Error inesperado: {e}")