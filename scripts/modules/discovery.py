#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de descubrimiento pasivo de activos para un dominio.
Fuentes utilizadas: crt.sh, DNSdumpster, Subfinder, consultas DNS y WHOIS.
"""

# ==================== IMPORTACIONES ====================
import requests          # Para hacer peticiones HTTP a crt.sh, DNSdumpster, etc.
import dns.resolver      # Para consultar registros DNS (A, MX, TXT, NS, SOA, AAAA)
import subprocess        # Para ejecutar subfinder como proceso externo
import re                # Para extraer subdominios del HTML de DNSdumpster
from typing import Set, Dict  # Para anotar tipos (mejora la legibilidad)
from .active_check import ActiveChecker  # Módulo propio para verificar actividad ICMP/TCP

# ==================== CLASE PRINCIPAL ====================
class PassiveDiscovery:
    """
    Clase que realiza descubrimiento pasivo de activos (subdominios, DNS, WHOIS)
    y opcionalmente verifica la actividad de los hosts encontrados mediante ICMP/TCP.
    """

    def __init__(self, domain: str):
        """
        Constructor.
        :param domain: dominio a analizar (ej: 'zunder.com')
        """
        self.domain = domain                     # Dominio objetivo
        self.subdomains: Set[str] = set()        # Conjunto para almacenar subdominios únicos
        self.dns_records: Dict = {}              # Diccionario para guardar registros DNS

    # ------------------------------------------------------------
    # 1. crt.sh: Certificate Transparency Logs
    # ------------------------------------------------------------
    def query_crtsh(self) -> Set[str]:
        """
        Consulta los logs de transparencia de certificados (crt.sh).
        Extrae subdominios de los campos 'name_value', 'common_name' y 'name'.
        Retorna el conjunto actualizado de subdominios.
        """
        print(f"[*] Consultando crt.sh para {self.domain}")
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        # El parámetro 'q=%.dominio' busca cualquier certificado que contenga el dominio.

        try:
            # Cabecera User-Agent para evitar bloqueos por parte de crt.sh
            response = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if response.status_code == 200:
                data = response.json()   # La respuesta es una lista de certificados en JSON

                # Primer recorrido: campos 'name_value' y 'common_name'
                for entry in data:
                    name_value = entry.get('name_value', '')
                    common_name = entry.get('common_name', '')
                    name = name_value or common_name   # Priorizar name_value
                    if name:
                        # Puede contener varios nombres separados por saltos de línea
                        if '\n' in name:
                            for sub in name.split('\n'):
                                sub = sub.strip().lower()
                                if sub.endswith(self.domain) and sub != self.domain:
                                    self.subdomains.add(sub)
                        else:
                            name = name.strip().lower()
                            if name.endswith(self.domain) and name != self.domain:
                                self.subdomains.add(name)

                # Segundo recorrido: campo 'name' (a veces aparece solo ahí)
                for entry in data:
                    if 'name' in entry:
                        name = entry['name'].strip().lower()
                        if name.endswith(self.domain) and name != self.domain:
                            self.subdomains.add(name)

                print(f"    [+] crt.sh: {len(self.subdomains)} subdominios encontrados")
                if self.subdomains:
                    print(f"    [+] Ejemplos: {list(self.subdomains)[:5]}")
            else:
                print(f"    [!] crt.sh respondió con código {response.status_code}")
        except Exception as e:
            print(f"    [!] Error en crt.sh: {e}")
        return self.subdomains

    # ------------------------------------------------------------
    # 2. DNSdumpster (público, sin API key)
    # ------------------------------------------------------------
    def query_dnsdumpster(self) -> Set[str]:
        """
        Consulta DNSdumpster.com realizando una petición POST con token CSRF.
        Extrae subdominios del HTML devuelto usando expresiones regulares.
        Retorna el conjunto actualizado de subdominios.
        """
        print(f"[*] Consultando DNSdumpster para {self.domain}")

        url = "https://dnsdumpster.com/"
        session = requests.Session()   # Mantiene cookies entre peticiones

        try:
            # 1) GET para obtener la cookie CSRF y el token
            response = session.get(url, timeout=15)
            csrf_token = None
            if 'csrftoken' in session.cookies:
                csrf_token = session.cookies['csrftoken']

            # 2) POST con el dominio y el token CSRF
            data = {'csrfmiddlewaretoken': csrf_token, 'targetip': self.domain}
            headers = {'Referer': url}
            response = session.post(url, data=data, headers=headers, timeout=30)

            # 3) Extraer subdominios del HTML usando regex
            # Busca cadenas que terminen en .dominio (ej: sub.zunder.com)
            subs = re.findall(r'[\w\.-]+\.' + re.escape(self.domain), response.text)
            for sub in subs:
                self.subdomains.add(sub.lower())
            print(f"    [+] DNSdumpster: {len(set(subs))} subdominios añadidos")
        except Exception as e:
            print(f"    [!] Error en DNSdumpster: {e}")
        return self.subdomains

    # ------------------------------------------------------------
    # 3. Subfinder (herramienta CLI, ejecución pasiva)
    # ------------------------------------------------------------
    def query_subfinder(self) -> Set[str]:
        """
        Ejecuta la herramienta subfinder en modo pasivo (sin escaneo activo).
        Captura su salida y añade los subdominios encontrados.
        Si subfinder no está instalado, lo indica y continúa (no crítico).
        """
        print(f"[*] Ejecutando subfinder para {self.domain}")
        try:
            # subfinder -d dominio -silent -timeout 10
            result = subprocess.run(
                ['subfinder', '-d', self.domain, '-silent', '-timeout', '10'],
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.strip() and line.strip().endswith(self.domain):
                        self.subdomains.add(line.strip().lower())
                print(f"    [+] Subfinder: {len(result.stdout.splitlines())} subdominios encontrados")
            else:
                print(f"    [!] Subfinder no devolvió resultados")
        except FileNotFoundError:
            print("    [!] Subfinder no instalado. Instálalo desde https://github.com/projectdiscovery/subfinder o con gestor de paquetes (brew, apt, etc.)")
        except subprocess.TimeoutExpired:
            print("    [!] Subfinder timeout - se omite para continuar")
        except Exception as e:
            print(f"    [!] Error en subfinder: {e}")
        return self.subdomains

    # ------------------------------------------------------------
    # 4. Consulta de registros DNS
    # ------------------------------------------------------------
    def query_dns_records(self) -> Dict:
        """
        Consulta los registros DNS públicos: A, AAAA, MX, TXT, NS, SOA.
        Almacena los resultados en self.dns_records.
        Retorna el diccionario con los registros.
        """
        print(f"[*] Consultando registros DNS de {self.domain}")
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                # Convertir cada respuesta a string y guardar en lista
                self.dns_records[record_type] = [str(rdata) for rdata in answers]
                print(f"    [+] {record_type}: {len(answers)} registros encontrados")
            except dns.resolver.NoAnswer:
                # El tipo de registro existe pero no hay respuestas
                self.dns_records[record_type] = []
            except Exception as e:
                print(f"    [!] Error en {record_type}: {e}")
                self.dns_records[record_type] = []
        return self.dns_records

    # ------------------------------------------------------------
    # 5. WHOIS
    # ------------------------------------------------------------
    def query_whois(self) -> Dict:
        """
        Consulta WHOIS del dominio usando la biblioteca 'whois'.
        Retorna un diccionario con registrador, fechas de creación/expiración y servidores NS.
        """
        print(f"[*] Consultando WHOIS de {self.domain}")
        import whois   # Importación local para evitar cargarla si no se usa
        try:
            w = whois.whois(self.domain)
            return {
                "registrar": str(w.registrar) if w.registrar else "No disponible",
                "creation_date": str(w.creation_date) if w.creation_date else "No disponible",
                "expiration_date": str(w.expiration_date) if w.expiration_date else "No disponible",
                "name_servers": w.name_servers if w.name_servers else []
            }
        except Exception as e:
            print(f"    [!] Error en WHOIS: {e}")
            return {"error": str(e)}

    # ------------------------------------------------------------
    # Método auxiliar para añadir subdominios desde fuentes externas
    # ------------------------------------------------------------
    def add_subdomains_from_list(self, new_subdomains: list):
        """
        Añade subdominios proporcionados por una lista externa (ej: desde threat_intel).
        Evita duplicados y verifica que terminen en el dominio principal.
        """
        if new_subdomains:
            for sub in new_subdomains:
                if sub and isinstance(sub, str) and sub.endswith(self.domain):
                    self.subdomains.add(sub.lower())
            print(f"    [+] Añadidos {len([s for s in new_subdomains if s])} subdominios de fuentes externas")

    # ------------------------------------------------------------
    # Método principal que ejecuta todo el flujo de descubrimiento
    # ------------------------------------------------------------
    def run_all(self, verificar_actividad: bool = True) -> Dict:
        """
        Ejecuta todos los módulos de descubrimiento:
          - crt.sh, DNSdumpster, subfinder, DNS, WHOIS.
        Opcionalmente, verifica la actividad de los subdominios mediante ICMP y TCP/80.
        Retorna un diccionario con:
          - domain, subdomains (lista ordenada), total_subdomains,
          - dns_records, whois, activos (resumen y resultados detallados)
        """
        print("\n" + "="*55)
        print("FASE 1: DESCUBRIMIENTO PASIVO DE ACTIVOS")
        print("="*55)
        print("Fuentes: crt.sh | DNSdumpster | Subfinder | DNS | WHOIS\n")

        # Ejecutar cada fuente de descubrimiento
        self.query_crtsh()
        self.query_dnsdumpster()
        self.query_subfinder()
        self.query_dns_records()
        whois_data = self.query_whois()

        # Verificación de actividad (ICMP + TCP) si se solicita y hay subdominios
        activos_info = {}
        if verificar_actividad and self.subdomains:
            print("\n" + "="*55)
            print("VERIFICACIÓN DE ACTIVIDAD DE SUBDOMINIOS")
            print("="*55)
            print("Métodos: ICMP (ping) → Si falla → TCP/80 (SYN+ACK)\n")

            checker = ActiveChecker()   # Instancia del verificador
            hosts_analizar = list(self.subdomains) + [self.domain]   # Incluir dominio principal

            resultados_actividad = checker.check_multiple_hosts(hosts_analizar, tcp_port=80)
            resumen = checker.generar_resumen(resultados_actividad)

            print("\n" + "-"*40)
            print(f"RESUMEN FINAL:")
            print(f"  • Total hosts analizados: {resumen['total_hosts']}")
            print(f"  • Hosts ACTIVOS: {resumen['activos']} (✓)")
            print(f"  • Hosts NO ACTIVOS: {resumen['no_activos']} (✗)")
            print(f"  • ICMP exitoso: {resumen['detectados_por_icmp']}")
            print(f"  • TCP/80 exitoso: {resumen['detectados_por_tcp']}")

            activos_info = {
                "resumen": resumen,
                "resultados_detallados": resultados_actividad
            }

        # Devolver todos los resultados en un diccionario
        return {
            "domain": self.domain,
            "subdomains": sorted(list(self.subdomains)),          # Lista ordenada alfabéticamente
            "total_subdomains": len(self.subdomains),
            "dns_records": self.dns_records,
            "whois": whois_data,
            "activos": activos_info
        }