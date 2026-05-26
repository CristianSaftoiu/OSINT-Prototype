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
import platform      # Para detectar SO (útil en mensajes multiplataforma, aunque no se usa directamente aquí)
from dotenv import load_dotenv  # Función que lee el archivo .env y lo carga en variables de entorno

# ============================================================
# CARGA DE VARIABLES DE ENTORNO
# ============================================================
load_dotenv()         # Busca archivo .env en el directorio actual y carga las variables
# Línea de depuración: comprueba si al menos la clave de Shodan se ha cargado (True/False)
print("[DEBUG] Variables de entorno cargadas:", os.getenv('SHODAN_API_KEY') is not None)

# ============================================================
# IMPORTACIÓN DE MÓDULOS PROPIOS (cada uno en scripts/modules/)
# ============================================================
from scripts.modules.discovery import PassiveDiscovery      # Fase 1: descubre subdominios, DNS, WHOIS, actividad
from scripts.modules.threat_intel import ThreatIntel        # Fase 2: consulta APIs de inteligencia de amenazas
from scripts.modules.report import ReportGenerator          # Fase 3: genera informes JSON, CSV, Markdown
from scripts.modules.darkweb_monitor import DarkWebMonitor  # Fase 4: busca en la dark web (Tor)

# ============================================================
# FUNCIONES AUXILIARES
# ============================================================
def print_banner(dominio):
    """Muestra un banner decorativo con el dominio que se va a analizar."""
    # El formato {dominio:<48} alinea el nombre del dominio a la izquierda en un espacio de 48 caracteres
    print(f"""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║     PROTOTIPO OSINT - {dominio:<48}                                          ║
    ║     Descubrimiento de activos expuestos                                      ║
    ║     Múltiples APIs: Shodan, Censys, VirusTotal, AlienVault, Hunter, etc.     ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """)

def validar_dominio(dominio):
    """Valida que el dominio tenga un formato correcto usando expresión regular.
    Retorna True si es válido, False en caso contrario."""
    # Patrón: letra/número al inicio, luego letras/números/puntos/guiones, y al menos un punto y 2 letras al final
    patron = r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(patron, dominio) is not None   # re.match devuelve objeto si coincide, sino None

# ============================================================
# FUNCIÓN PRINCIPAL
# ============================================================
def main():
    """Función que orquesta todo el análisis (fases 1 a 4)."""
    
    # --- SOLICITAR DOMINIO AL USUARIO ---
    print("\n" + "="*60)          # Línea separadora de 60 caracteres "="
    print("    PROTOTIPO OSINT - HERRAMIENTA DE RECONOCIMIENTO ")
    print("="*60)
    
    while True:                   # Bucle infinito hasta que se introduzca un dominio válido
        # input() muestra el mensaje y espera que el usuario escriba
        dominio = input("   ▶ Introduzca el dominio a analizar (ej: google.com): ").strip().lower()
        # .strip() elimina espacios al inicio/final; .lower() pasa a minúsculas
        
        if not dominio:           # Si el usuario no escribió nada (cadena vacía)
            print("   ⚠️  No ha introducido ningún dominio. Inténtelo de nuevo.\n")
            continue              # Vuelve al inicio del bucle
        
        if not validar_dominio(dominio):   # Si el formato no es correcto
            print(f"   ⚠️  '{dominio}' no parece un dominio válido. Inténtelo de nuevo.")
            print("      Formato correcto: ejemplo.com, dominio.es, sub.dominio.org\n")
            continue              # Vuelve a preguntar
        
        # Si llegamos aquí, el dominio es válido
        print(f"\n   ✅ Dominio aceptado: {dominio}")
        print("   ⏳ Iniciando análisis...\n")
        break                     # Salimos del bucle while
    
    # Mostrar el banner decorativo
    print_banner(dominio)
    
    # Guardar el instante actual (en segundos desde el 1/1/1970) para medir duración total
    start_time = time.time()
    
    # ==================== FASE 1: DESCUBRIMIENTO ====================
    print("\n" + "="*60)
    print("FASE 1 DE 4 - DESCUBRIMIENTO DE ACTIVOS")
    print("="*60)
    
    # Crear un objeto de la clase PassiveDiscovery, pasándole el dominio
    discovery = PassiveDiscovery(dominio)
    # Llamar al método run_all() que ejecuta todas las técnicas de descubrimiento
    discovery_results = discovery.run_all()
    # discovery_results es un diccionario con: subdomains, dns_records, whois, activos (verificación ICMP/TCP)
    
    # ==================== FASE 2: THREAT INTELLIGENCE ====================
    print("\n" + "="*60)
    print("FASE 2 DE 4 - THREAT INTELLIGENCE")
    print("="*60)
    
    # Crear objeto de la clase ThreatIntel
    threat = ThreatIntel(dominio)
    # Ejecutar todas las consultas a APIs externas (VirusTotal, Shodan, etc.)
    threat_results = threat.run_all()
    # threat_results contiene reputación, correos, geolocalización, etc.
    
    # ==================== COMBINAR SUBDOMINIOS (de múltiples fuentes) ====================
    print("\n" + "="*60)
    print("COMBINANDO RESULTADOS DE MÚLTIPLES FUENTES")
    print("="*60)
    
    # Extraer subdominios que VirusTotal haya encontrado (si los hay)
    subdominios_vt = threat_results.get('subdomains_from_virustotal', [])
    
    # Extraer subdominios de los resultados de urlscan.io
    subdominios_urlscan = []
    # threat_results['urlscan'] es un diccionario; .get('results', []) devuelve lista vacía si no existe
    for result in threat_results.get('urlscan', {}).get('results', []):
        domain_found = result.get('domain', '')
        # Condición: que no sea el dominio principal y que termine con él (ej: panel.zunder.com)
        if domain_found and domain_found != dominio and domain_found.endswith(dominio):
            subdominios_urlscan.append(domain_found)
    
    # Usamos un conjunto (set) para eliminar duplicados automáticamente
    todos_subdominios = set(discovery_results.get('subdomains', []))
    todos_subdominios.update(subdominios_vt)        # añadir los de VT
    todos_subdominios.update(subdominios_urlscan)   # añadir los de urlscan
    
    # Actualizar el diccionario discovery_results con la lista ordenada y el total
    discovery_results['subdomains'] = sorted(list(todos_subdominios))
    discovery_results['total_subdomains'] = len(todos_subdominios)
    
    # Mostrar estadísticas de la combinación
    print(f"   [+] Subdominios de crt.sh/Subfinder: {len(discovery_results.get('subdomains', []))}")
    print(f"   [+] Subdominios de VirusTotal: {len(subdominios_vt)}")
    print(f"   [+] Subdominios de urlscan.io: {len(subdominios_urlscan)}")
    print(f"   [+] TOTAL subdominios únicos: {discovery_results['total_subdomains']}")
    
    # ==================== FASE 3: GENERAR INFORMES ====================
    print("\n" + "="*60)
    print("FASE 3 DE 4 - GENERANDO INFORMES")
    print("="*60)
    
    # Crear generador de informes, especificando la carpeta de salida "outputs"
    reporter = ReportGenerator("outputs")
    
    # Guardar todo el análisis en un archivo JSON (estructura completa y fácil de parsear)
    reporter.to_json({
        "dominio_analizado": dominio,
        "discovery": discovery_results,
        "threat_intel": threat_results,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")   # Formato: AAAA-MM-DD HH:MM:SS
    })
    
    # Guardar solo la lista de subdominios en formato CSV (compatible con Excel)
    reporter.to_csv(discovery_results.get('subdomains', []))
    
    # Guardar un informe legible en Markdown (secciones con títulos y tablas)
    reporter.to_markdown(discovery_results, threat_results)
    
    # ==================== FASE 4: DARK WEB MONITORING ====================
    print("\n" + "="*60)
    print("FASE 4 DE 4 - MONITORIZACIÓN EN DARK WEB (Tor)")
    print("="*60)
    print("   Esta fase busca en la red Tor (dark web) posibles menciones")
    print("   o enlaces relacionados con el dominio.\n")
    
    # Preguntar al usuario si quiere realizar la búsqueda (consume tiempo y requiere Tor)
    respuesta = input("   ¿Deseas realizar la búsqueda en la Dark Web? (s/n): ").strip().lower()
    
    if respuesta == 's':
        print("\n   ⏳ Conectando a la red Tor y realizando la búsqueda...")
        dw = DarkWebMonitor(dominio)          # Crear objeto con la keyword (dominio)
        darkweb_results = dw.run_all()        # Ejecutar búsqueda multi-motor + crawling
        threat_results["darkweb"] = darkweb_results   # Añadir al diccionario de threat intel
        # Regenerar el informe Markdown para que incluya la nueva sección de dark web
        reporter.to_markdown(discovery_results, threat_results)
        print("   ✅ Resultados de Dark Web añadidos al informe.\n")
    else:
        # Si el usuario omite la dark web, guardamos un estado "skipped"
        threat_results["darkweb"] = {"status": "skipped"}
        print("   ⏩ Búsqueda en Dark Web omitida por el usuario.\n")
    
    # ==================== RESUMEN FINAL (en consola) ====================
    elapsed = time.time() - start_time   # Tiempo total transcurrido
    
    print("\n" + "="*60)
    print("RESUMEN DE HALLAZGOS")
    print("="*60)
    
    print(f"\n  📊 ESTADÍSTICAS:")
    print(f"     • Dominio analizado: {dominio}")
    print(f"     • Subdominios únicos detectados: {discovery_results['total_subdomains']}")
    print(f"     • Tipos de registros DNS consultados: {len(discovery_results.get('dns_records', {}))}")
    print(f"     • IP resuelta: {threat_results.get('ip_address', 'N/D')}")
    
    # Mostrar información de verificación de actividad (si existe)
    activos_info = discovery_results.get('activos', {})
    if activos_info:
        print(f"\n  🟢 VERIFICACIÓN DE ACTIVIDAD:")
        print(f"     • Hosts ACTIVOS: {activos_info.get('resumen', {}).get('activos', 0)}/{activos_info.get('resumen', {}).get('total_hosts', 0)}")
        print(f"     • Detectados por ICMP (ping): {activos_info.get('resumen', {}).get('detectados_por_icmp', 0)}")
        print(f"     • Detectados por TCP/80: {activos_info.get('resumen', {}).get('detectados_por_tcp', 0)}")
    
    # Mostrar un pequeño resumen de la dark web (solo si se ejecutó)
    dw_res = threat_results.get("darkweb", {})
    if dw_res.get("status") == "success":
        print(f"\n  🌑 DARK WEB:")
        print(f"     • Búsqueda realizada para: {dw_res.get('keyword', 'N/A')}")
        print(f"     • Enlaces .onion encontrados: {dw_res.get('total', 0)}")
    elif dw_res.get("status") == "error":
        print(f"\n  🌑 DARK WEB:")
        print(f"     • Error: {dw_res.get('message', 'Desconocido')}")
    
    # Listar los archivos de salida generados
    print(f"\n  📁 ARCHIVOS GENERADOS:")
    print(f"     • outputs/activos_*.json - Datos completos en JSON")
    print(f"     • outputs/subdominios_*.csv - Inventario de subdominios")
    print(f"     • outputs/informe_*.md - Informe completo en Markdown")
    
    print(f"\n  ⏱️  Tiempo total de ejecución: {elapsed:.2f} segundos")
    
    print("\n" + "="*60)
    print("✅ PROTOTIPO EJECUTADO CORRECTAMENTE")
    print("="*60)


# ============================================================
# PUNTO DE ENTRADA (CUANDO SE EJECUTA EL SCRIPT DIRECTAMENTE)
# ============================================================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # El usuario presionó Ctrl+C durante la ejecución
        print("\n\n[!] Ejecución interrumpida por el usuario")
    except Exception as e:
        # Cualquier otro error inesperado
        print(f"\n[!] Error inesperado: {e}")