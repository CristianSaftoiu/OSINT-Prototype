"""
Módulo de descubrimiento pasivo de activos para zunder.com
APIs incluidas: crt.sh, DNSdumpster, Subfinder, consultas DNS, WHOIS
"""

import requests
import dns.resolver
import subprocess
import re
from typing import Set, Dict
from .active_check import ActiveChecker

class PassiveDiscovery:
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains: Set[str] = set()
        self.dns_records: Dict = {}
        
    def query_crtsh(self) -> Set[str]:
        """Consulta Certificate Transparency Logs (crt.sh)"""
        print(f"[*] Consultando crt.sh para {self.domain}")
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
    
        try:
            response = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    # Probar diferentes campos donde pueden estar los nombres
                    name_value = entry.get('name_value', '')
                    common_name = entry.get('common_name', '')
                    name = name_value or common_name
                
                    if name:
                        # Limpiar y extraer subdominios
                        if '\n' in name:
                            for sub in name.split('\n'):
                                sub = sub.strip().lower()
                                if sub.endswith(self.domain) and sub != self.domain:
                                    self.subdomains.add(sub)
                        else:
                            name = name.strip().lower()
                            if name.endswith(self.domain) and name != self.domain:
                                self.subdomains.add(name)
            
                # También buscar en el campo 'name' de cada entrada
                for entry in data:
                    if 'name' in entry:
                        name = entry['name'].strip().lower()
                        if name.endswith(self.domain) and name != self.domain:
                            self.subdomains.add(name)
            
                print(f"    [+] crt.sh: {len(self.subdomains)} subdominios encontrados")
            
                # Mostrar algunos ejemplos
                if self.subdomains:
                    print(f"    [+] Ejemplos: {list(self.subdomains)[:5]}")
            else:
                print(f"    [!] crt.sh respondió con código {response.status_code}")
        except Exception as e:
            print(f"    [!] Error en crt.sh: {e}")
        return self.subdomains
    
    def query_dnsdumpster(self) -> Set[str]:
        """Consulta DNSdumpster - sin API key necesaria"""
        print(f"[*] Consultando DNSdumpster para {self.domain}")
        
        url = "https://dnsdumpster.com/"
        session = requests.Session()
        
        try:
            # Obtener token CSRF
            response = session.get(url, timeout=15)
            csrf_token = None
            if 'csrftoken' in session.cookies:
                csrf_token = session.cookies['csrftoken']
            
            # Enviar dominio
            data = {'csrfmiddlewaretoken': csrf_token, 'targetip': self.domain}
            headers = {'Referer': url}
            
            response = session.post(url, data=data, headers=headers, timeout=30)
            # Extraer subdominios del HTML
            subs = re.findall(r'[\w\.-]+\.' + re.escape(self.domain), response.text)
            for sub in subs:
                self.subdomains.add(sub.lower())
            print(f"    [+] DNSdumpster: {len(set(subs))} subdominios añadidos")
        except Exception as e:
            print(f"    [!] Error en DNSdumpster: {e}")
        return self.subdomains
    
    def query_subfinder(self) -> Set[str]:
        """Ejecuta subfinder en modo pasivo"""
        print(f"[*] Ejecutando subfinder para {self.domain}")
        try:
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
            print("    [!] Subfinder no instalado. Instalar con: brew install subfinder")
        except subprocess.TimeoutExpired:
            print("    [!] Subfinder timeout - se omite para continuar")
        except Exception as e:
            print(f"    [!] Error en subfinder: {e}")
        return self.subdomains
    
    def query_dns_records(self) -> Dict:
        """Consulta registros DNS públicos: A, MX, TXT, NS, SOA, AAAA"""
        print(f"[*] Consultando registros DNS de {self.domain}")
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                self.dns_records[record_type] = [str(rdata) for rdata in answers]
                print(f"    [+] {record_type}: {len(answers)} registros encontrados")
            except dns.resolver.NoAnswer:
                self.dns_records[record_type] = []
            except Exception as e:
                print(f"    [!] Error en {record_type}: {e}")
                self.dns_records[record_type] = []
        return self.dns_records
    
    def query_whois(self) -> Dict:
        """Consulta WHOIS del dominio"""
        print(f"[*] Consultando WHOIS de {self.domain}")
        import whois
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
    
    def add_subdomains_from_list(self, new_subdomains: list):
        """Añade subdominios desde una lista externa"""
        if new_subdomains:
            for sub in new_subdomains:
                if sub and isinstance(sub, str) and sub.endswith(self.domain):
                    self.subdomains.add(sub.lower())
            print(f"    [+] Añadidos {len([s for s in new_subdomains if s])} subdominios de fuentes externas")
            
    
    def run_all(self, verificar_actividad: bool = True) -> Dict:
        """Ejecuta todos los módulos de descubrimiento"""
        print("\n" + "="*55)
        print("FASE 1: DESCUBRIMIENTO PASIVO DE ACTIVOS")
        print("="*55)
        print("Fuentes: crt.sh | DNSdumpster | Subfinder | DNS | WHOIS\n")
    
        self.query_crtsh()
        self.query_dnsdumpster()
        self.query_subfinder()
        self.query_dns_records()
        whois_data = self.query_whois()
    
        # Verificar actividad de subdominios
        activos_info = {}
        if verificar_actividad and self.subdomains:
            print("\n" + "="*55)
            print("VERIFICACIÓN DE ACTIVIDAD DE SUBDOMINIOS")
            print("="*55)
            print("Métodos: ICMP (ping) → Si falla → TCP/80 (SYN+ACK)\n")
            
            checker = ActiveChecker()
            hosts_analizar = list(self.subdomains) + [self.domain]
            
            # Verificar actividad
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
    
        return {
            "domain": self.domain,
            "subdomains": sorted(list(self.subdomains)),
            "total_subdomains": len(self.subdomains),
            "dns_records": self.dns_records,
            "whois": whois_data,
            "activos": activos_info
        }