"""
Módulo de Threat Intelligence - Versión COMPLETA con TODAS las APIs
APIs incluidas: Shodan, Censys, VirusTotal, AlienVault, IPinfo, IPdata,
Hunter, Netlas, urlscan, AbuseIPDB, BeVigil, GitHub, GitLab, Wappalyzer (guiado), BuiltWith (guiado)
"""

import os
import requests
import socket
from typing import Dict

class ThreatIntel:
    def __init__(self, domain: str):
        self.domain = domain
        self.results = {}
        self.subdomains_from_vt = [] 
        
        # Cargar API keys desde environment variables
        self.shodan_api_key = os.getenv("SHODAN_API_KEY", "")
        self.censys_api_id = os.getenv("CENSYS_API_ID", "")
        self.censys_api_secret = os.getenv("CENSYS_API_SECRET", "")
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.alienvault_api_key = os.getenv("ALIENVAULT_API_KEY", "")
        self.hunter_api_key = os.getenv("HUNTER_API_KEY", "")
        self.ipinfo_api_key = os.getenv("IPINFO_API_KEY", "")
        self.ipdata_api_key = os.getenv("IPDATA_API_KEY", "")
        self.netlas_api_key = os.getenv("NETLAS_API_KEY", "")
        self.urlscan_api_key = os.getenv("URLSCAN_API_KEY", "")
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self.bevigil_api_key = os.getenv("BEVIGIL_API_KEY", "")
        
        # Resolver IP del dominio
        try:
            self.ip_address = socket.gethostbyname(domain)
            print(f"    [+] IP resuelta: {self.ip_address}")
        except:
            self.ip_address = None
            print(f"    [!] No se pudo resolver IP de {domain}")
    
    # ==================== API 1: VIRUSTOTAL ====================
    def query_virustotal(self) -> Dict:
        """VirusTotal - Reputación del dominio y subdominios"""
        if not self.virustotal_api_key:
            return {"status": "no_api_key", "message": "Configurar VIRUSTOTAL_API_KEY en .env"}
        
        print(f"[*] VirusTotal: consultando reputación de {self.domain}")
        
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}"
        headers = {"x-apikey": self.virustotal_api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                # Extraer subdominios de VirusTotal
                if attributes.get('subdomains'):
                    self.subdomains_from_vt = attributes.get('subdomains', [])
                
                return {
                    "status": "ok",
                    "reputation": attributes.get('reputation', 0),
                    "last_analysis_stats": attributes.get('last_analysis_stats', {}),
                    "categories": attributes.get('categories', {}),
                    "subdomains": attributes.get('subdomains', [])[:15]
                }
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # ==================== API 2: SHODAN ====================
    def query_shodan(self) -> Dict:
        """Shodan - Puertos, servicios y vulnerabilidades"""
        if not self.shodan_api_key:
            return {"status": "no_api_key", "message": "Configurar SHODAN_API_KEY en .env"}
        
        if not self.ip_address:
            return {"status": "error", "message": "No se pudo resolver IP"}
        
        print(f"[*] Shodan: consultando IP {self.ip_address}")
        
        url = f"https://api.shodan.io/shodan/host/{self.ip_address}?key={self.shodan_api_key}"
        
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "ok",
                    "ip": self.ip_address,
                    "ports": data.get('ports', []),
                    "hostnames": data.get('hostnames', []),
                    "vulnerabilities": data.get('vulnerabilities', []),
                    "tags": data.get('tags', [])
                }
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # ==================== API 3: CENSYS ====================
    def query_censys(self) -> Dict:
        """Censys - Certificados y servicios expuestos"""
        if not self.censys_api_id or not self.censys_api_secret:
            return {"status": "no_api_key", "message": "Configurar CENSYS_API_ID y CENSYS_API_SECRET en .env"}
        
        print(f"[*] Censys: consultando certificados de {self.domain}")
        
        try:
            from censys.search import CensysCertificates
            censys = CensysCertificates(api_id=self.censys_api_id, api_secret=self.censys_api_secret)
            query = f"parsed.names: {self.domain}"
            results = censys.search(query, per_page=10)
            
            certificates = []
            for cert in results():
                certificates.append({
                    "names": cert.get('parsed', {}).get('names', []),
                    "fingerprint": cert.get('fingerprint', '')[:16]
                })
            
            return {
                "status": "ok",
                "total_certificates": len(certificates),
                "certificates": certificates[:10]
            }
        except ImportError:
            return {"status": "error", "message": "Instalar: pip install censys"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # ==================== API 4: ALIENVAULT OTX ====================
    def query_alienvault(self) -> Dict:
        """AlienVault OTX - Indicadores de amenazas"""
        if not self.alienvault_api_key:
            return {"status": "no_api_key", "message": "Configurar ALIENVAULT_API_KEY en .env"}
        
        print(f"[*] AlienVault OTX: consultando {self.domain}")
        
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/general"
        headers = {"X-OTX-API-KEY": self.alienvault_api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "ok",
                    "pulse_count": data.get('pulse_info', {}).get('count', 0),
                    "reputation": data.get('reputation', "N/A"),
                    "validation": data.get('validation', [])[:5]
                }
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # ==================== API 5: IPINFO ====================
    def query_ipinfo(self) -> Dict:
        """IPinfo - Geolocalización y ASN"""
        if not self.ipinfo_api_key:
            return {"status": "no_api_key", "message": "Configurar IPINFO_API_KEY en .env"}
        
        if not self.ip_address:
            return {"status": "error", "message": "No hay IP para consultar"}
        
        print(f"[*] IPinfo: geolocalizando {self.ip_address}")
        
        url = f"https://ipinfo.io/{self.ip_address}?token={self.ipinfo_api_key}"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "ok",
                    "ip": self.ip_address,
                    "city": data.get('city', 'N/A'),
                    "country": data.get('country', 'N/A'),
                    "asn": data.get('asn', 'N/A'),
                    "org": data.get('org', 'N/A')
                }
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # ==================== API 6: IPDATA ====================
    def query_ipdata(self) -> Dict:
        """IPdata - Geolocalización y reputación"""
        if not self.ipdata_api_key:
            return {"status": "no_api_key", "message": "Configurar IPDATA_API_KEY en .env"}
        
        if not self.ip_address:
            return {"status": "error", "message": "No hay IP para consultar"}
        
        print(f"[*] IPdata: consultando {self.ip_address}")
        
        url = f"https://api.ipdata.co/{self.ip_address}?api-key={self.ipdata_api_key}"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "ok",
                    "ip": self.ip_address,
                    "city": data.get('city', 'N/A'),
                    "country_name": data.get('country_name', 'N/A'),
                    "asn": data.get('asn', {}).get('asn', 'N/A'),
                    "is_tor": data.get('threat', {}).get('is_tor', False),
                    "is_proxy": data.get('threat', {}).get('is_proxy', False)
                }
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # ==================== API 7: HUNTER.IO ====================
    def query_hunter(self) -> Dict:
        """Hunter.io - Correos electrónicos asociados al dominio"""
        if not self.hunter_api_key:
            return {"status": "no_api_key", "message": "Configurar HUNTER_API_KEY en .env"}
        
        print(f"[*] Hunter.io: buscando emails en {self.domain}")
        
        url = f"https://api.hunter.io/v2/domain-search?domain={self.domain}&api_key={self.hunter_api_key}"
        
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                emails = data.get('data', {}).get('emails', [])
                return {
                    "status": "ok",
                    "total_emails": len(emails),
                    "emails": [{"value": e['value'], "type": e.get('type', 'N/A')} for e in emails[:10]]
                }
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # ==================== API 8: NETLAS ====================
    def query_netlas(self) -> Dict:
        """Netlas - Búsqueda de activos expuestos"""
        if not self.netlas_api_key:
            return {"status": "no_api_key", "message": "Configurar NETLAS_API_KEY en .env"}
        
        print(f"[*] Netlas: buscando activos de {self.domain}")
        
        url = f"https://app.netlas.io/api/hosts/search/?q=domain:{self.domain}"
        headers = {"X-API-Key": self.netlas_api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "ok",
                    "total": data.get('total', 0),
                    "hosts": data.get('items', [])[:5]
                }
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # ==================== API 9: URLSCAN.IO ====================
    def query_urlscan(self) -> Dict:
        """urlscan.io - Búsqueda de dominios en URLs"""
        if not self.urlscan_api_key:
            return {"status": "no_api_key", "message": "Configurar URLSCAN_API_KEY en .env"}
        
        print(f"[*] urlscan.io: buscando {self.domain}")
        
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
        headers = {"API-Key": self.urlscan_api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "ok",
                    "total": data.get('total', 0),
                    "results": [{"url": r['page']['url'], "domain": r['page']['domain']} 
                               for r in data.get('results', [])[:5]]
                }
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # ==================== API 10: ABUSEIPDB ====================
    def query_abuseipdb(self) -> Dict:
        """AbuseIPDB - Reputación de IP"""
        if not self.abuseipdb_api_key:
            return {"status": "no_api_key", "message": "Configurar ABUSEIPDB_API_KEY en .env"}
        
        if not self.ip_address:
            return {"status": "error", "message": "No hay IP para consultar"}
        
        print(f"[*] AbuseIPDB: consultando reputación de {self.ip_address}")
        
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {'ipAddress': self.ip_address, 'maxAgeInDays': '90'}
        headers = {'Key': self.abuseipdb_api_key, 'Accept': 'application/json'}
        
        try:
            response = requests.get(url, headers=headers, params=querystring, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "ok",
                    "ip": self.ip_address,
                    "abuse_score": data['data']['abuseConfidenceScore'],
                    "total_reports": data['data']['totalReports'],
                    "country": data['data'].get('countryCode', 'N/A')
                }
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # ==================== API 11: BEVIGIL ====================
    def query_bevigil(self) -> Dict:
        """BeVigil - Subdominios y endpoints"""
        if not self.bevigil_api_key:
            return {"status": "no_api_key", "message": "Configurar BEVIGIL_API_KEY en .env"}
        
        print(f"[*] BeVigil: buscando subdominios de {self.domain}")
        
        url = f"https://api.bevigil.com/domain/{self.domain}/subdomains"
        headers = {"X-Api-Key": self.bevigil_api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "ok",
                    "subdomains": data.get('subdomains', [])[:20]
                }
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # ==================== API 12: GITHUB (sin API key, público) ====================
    def query_github(self) -> Dict:
        """GitHub - Búsqueda pública de menciones del dominio"""
        print(f"[*] GitHub: buscando menciones de {self.domain}")
        
        url = f"https://api.github.com/search/code?q={self.domain}"
        headers = {"Accept": "application/vnd.github.v3+json"}
        
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "ok",
                    "total_count": data.get('total_count', 0),
                    "items": [{"repo": i['repository']['full_name'], "path": i['path']} 
                             for i in data.get('items', [])[:5]]
                }
            return {"status": "error", "code": response.status_code, "message": "Límite de GitHub sin autenticación"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # ==================== API 13: GITLAB (sin API key, público) ====================
    def query_gitlab(self) -> Dict:
        """GitLab - Búsqueda pública de menciones del dominio"""
        print(f"[*] GitLab: buscando menciones de {self.domain}")
        
        url = f"https://gitlab.com/api/v4/search?scope=projects&search={self.domain}"
        
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "ok",
                    "total_count": len(data),
                    "items": [{"name": p['name'], "path": p['path_with_namespace']} 
                             for p in data[:5]]
                }
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # ==================== HERRAMIENTAS GUIADAS (sin API) ====================
    def query_wappalyzer_guide(self) -> Dict:
        """Wappalyzer - Guía para uso manual (no tiene API pública gratis)"""
        return {
            "status": "manual",
            "message": "Wappalyzer no tiene API pública gratuita",
            "instructions": "Instalar extensión de navegador Wappalyzer y visitar https://" + self.domain,
            "url": f"https://www.wappalyzer.com/technologies/?q={self.domain}"
        }
    
    def query_builtwith_guide(self) -> Dict:
        """BuiltWith - Guía para uso manual (no tiene API pública gratis)"""
        return {
            "status": "manual",
            "message": "BuiltWith no tiene API pública gratuita",
            "instructions": "Visitar https://builtwith.com/ y buscar el dominio",
            "url": f"https://builtwith.com/{self.domain}"
        }
    
    # ==================== EJECUCIÓN COMPLETA ====================
    def run_all(self) -> Dict:
        """Ejecuta TODAS las consultas de threat intelligence"""
        print("\n" + "="*55)
        print("FASE 2: THREAT INTELLIGENCE - MÚLTIPLES APIS")
        print("="*55)
        print("APIs a consultar: Shodan, Censys, VirusTotal, AlienVault, IPinfo,\n")
        print("IPdata, Hunter, Netlas, urlscan, AbuseIPDB, BeVigil, GitHub, GitLab\n")
        
        results = {
            "domain": self.domain,
            "ip_address": self.ip_address,
            "virustotal": self.query_virustotal(),
            "shodan": self.query_shodan(),
            "censys": self.query_censys(),
            "alienvault": self.query_alienvault(),
            "ipinfo": self.query_ipinfo(),
            "ipdata": self.query_ipdata(),
            "hunter": self.query_hunter(),
            "netlas": self.query_netlas(),
            "urlscan": self.query_urlscan(),
            "abuseipdb": self.query_abuseipdb(),
            "bevigil": self.query_bevigil(),
            "github": self.query_github(),
            "gitlab": self.query_gitlab(),
            "wappalyzer_guide": self.query_wappalyzer_guide(),
            "builtwith_guide": self.query_builtwith_guide(),
            "subdomains_from_virustotal": self.subdomains_from_vt  # <--- CORREGIDO
        }
        
        return results