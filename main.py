#!/usr/bin/env python3

"""
Prototipo OSINT - Descubrimiento pasivo de activos + monitorización
Uso: python main.py
Al ejecutar, preguntará el dominio a analizar.
Ejemplo: zunder.com, google.com, microsoft.com
"""

# ==================== IMPORTACIONES ====================

import time  # Para medir el tiempo de ejecución
import os    # Para acceder a variables de entorno y rutas del sistema
import re    # Expresiones regulares (para validar el formato del dominio)
from dotenv import load_dotenv  # Función para cargar API keys desde archivo .env

load_dotenv()  # Lee el archivo .env y carga las variables

from scripts.modules.discovery import PassiveDiscovery      # Fase 1
from scripts.modules.threat_intel import ThreatIntel        # Fase 2
from scripts.modules.report import ReportGenerator          # Fase 3
from scripts.modules.darkweb_monitor import DarkWebMonitor  # Fase 4 (Dark Web)

# ==================== FUNCIONES AUXILIARES ====================

def print_banner(dominio):
    """Muestra un banner decorativo con el dominio a analizar"""
    print(f"""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║     PROTOTIPO OSINT - {dominio:<48}                                          ║
    ║     Descubrimiento pasivo de activos expuestos                               ║
    ║     Múltiples APIs: Shodan, Censys, VirusTotal, AlienVault, Hunter, etc.     ║
    ║     Metodología NO intrusiva / Solo fuentes públicas                         ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """)

def validar_dominio(dominio):
    """Valida que el dominio tenga un formato correcto usando expresiones regulares"""
    patron = r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(patron, dominio) is not None

# ==================== FUNCIÓN PRINCIPAL ====================

def main():
    """Función principal que orquesta todo el prototipo"""
    
    # ----- SOLICITAR DOMINIO AL USUARIO -----
    print("\n" + "="*60)
    print("    PROTOTIPO OSINT - HERRAMIENTA DE RECONOCIMIENTO PASIVO")
    print("="*60)
    print("\n   Este prototipo realiza consultas PASIVAS a fuentes públicas.")
    print("   No se realiza ningún escaneo activo contra los sistemas objetivo.\n")
    
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
    
    # ==================== FASE 3: GENERAR INFORMES ====================
    print("\n" + "="*60)
    print("FASE 3 DE 4 - GENERANDO INFORMES")
    print("="*60)
    
    reporter = ReportGenerator("outputs")
    
    reporter.to_json({
        "dominio_analizado": dominio,
        "discovery": discovery_results,
        "threat_intel": threat_results,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })
    reporter.to_csv(discovery_results.get('subdomains', []))
    reporter.to_markdown(discovery_results, threat_results)
    
    # ==================== FASE 4: DARK WEB MONITORING ====================
    print("\n" + "="*60)
    print("FASE 4 DE 4 - MONITORIZACIÓN EN DARK WEB (Tor)")
    print("="*60)
    print("   Esta fase busca en la red Tor (dark web) posibles menciones")
    print("   o enlaces relacionados con el dominio.\n")
    
    respuesta = input("   ¿Deseas realizar la búsqueda en la Dark Web? (s/n): ").strip().lower()
    if respuesta == 's':
        print("\n   ⏳ Conectando a la red Tor y realizando la búsqueda...")
        dw = DarkWebMonitor(dominio)
        darkweb_results = dw.run_all()
        threat_results["darkweb"] = darkweb_results
        # Una vez obtenidos los resultados, actualizamos el informe Markdown para que incluya la dark web
        reporter.to_markdown(discovery_results, threat_results)
        print("   ✅ Resultados de Dark Web añadidos al informe.\n")
    else:
        threat_results["darkweb"] = {"status": "skipped"}
        print("   ⏩ Búsqueda en Dark Web omitida por el usuario.\n")
    
    # ==================== RESUMEN FINAL ====================
    elapsed = time.time() - start_time
    
    print("\n" + "="*60)
    print("RESUMEN DE HALLAZGOS")
    print("="*60)
    
    print(f"\n  📊 ESTADÍSTICAS:")
    print(f"     • Dominio analizado: {dominio}")
    print(f"     • Subdominios únicos detectados: {discovery_results['total_subdomains']}")
    print(f"     • Tipos de registros DNS consultados: {len(discovery_results.get('dns_records', {}))}")
    print(f"     • IP resuelta: {threat_results.get('ip_address', 'N/D')}")
    
    activos_info = discovery_results.get('activos', {})
    if activos_info:
        print(f"\n  🟢 VERIFICACIÓN DE ACTIVIDAD:")
        print(f"     • Hosts ACTIVOS: {activos_info.get('resumen', {}).get('activos', 0)}/{activos_info.get('resumen', {}).get('total_hosts', 0)}")
        print(f"     • Detectados por ICMP (ping): {activos_info.get('resumen', {}).get('detectados_por_icmp', 0)}")
        print(f"     • Detectados por TCP/80: {activos_info.get('resumen', {}).get('detectados_por_tcp', 0)}")
    
    # Mostrar resumen de la dark web si se ejecutó
    dw_res = threat_results.get("darkweb", {})
    if dw_res.get("status") == "success":
        print(f"\n  🌑 DARK WEB:")
        print(f"     • Búsqueda realizada para: {dw_res.get('keyword', 'N/A')}")
        print(f"     • Enlaces .onion encontrados: {dw_res.get('total', 0)}")
    elif dw_res.get("status") == "error":
        print(f"\n  🌑 DARK WEB:")
        print(f"     • Error: {dw_res.get('message', 'Desconocido')}")
    
    print(f"\n  📁 ARCHIVOS GENERADOS:")
    print(f"     • outputs/activos_*.json - Datos completos en JSON")
    print(f"     • outputs/subdominios_*.csv - Inventario de subdominios")
    print(f"     • outputs/informe_*.md - Informe completo en Markdown")
    
    print(f"\n  ⏱️  Tiempo total de ejecución: {elapsed:.2f} segundos")
    
    print("\n" + "="*60)
    print("✅ PROTOTIPO EJECUTADO CORRECTAMENTE")
    print("="*60)
    print("\n  📌 NOTAS IMPORTANTES:")
    print("     • Wappalyzer y BuiltWith no tienen API pública gratuita")
    print("     • Se incluyen guías de uso manual para estas herramientas")
    print("     • Todas las consultas realizadas son PASIVAS y NO intrusivas")
    print("     • Para mejores resultados, configura las API keys en .env")
    print("     • La búsqueda en Dark Web requiere Tor activo: 'brew services start tor'\n")

# ==================== PUNTO DE ENTRADA ====================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Ejecución interrumpida por el usuario")
    except Exception as e:
        print(f"\n[!] Error inesperado: {e}")