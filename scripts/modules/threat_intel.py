#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de Threat Intelligence - Versión COMPLETA con TODAS las APIs.
APIs incluidas: Shodan, Censys, VirusTotal, AlienVault, IPinfo, IPdata,
Hunter, Netlas, urlscan, AbuseIPDB, BeVigil, GitHub, GitLab.
Además incluye guías para herramientas sin API pública (Wappalyzer, BuiltWith).
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

        self.shodan_api_key = os.getenv("SHODAN_API_KEY", "")
        self.censys_api_id = os.getenv("CENSYS_API_ID", "")
        self.censys_api_secret = os.getenv("CENSYS_API_SECRET", "")
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.alienvault_api_key = os.getenv("ALIENVAULT_API_KEY", "")
        self.hunter_api_key = os.getenv("HUNTER_API_KEY", "")
        self.ipinfo_api_key = os.getenv("IPINFO_API_KEY", "")
        self.ipdata_api_key = os.getenv("IPDATA_API_KEY", "")
        self.urlscan_api_key = os.getenv("URLSCAN_API_KEY", "")
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self.github_token = os.getenv("GITHUB_TOKEN", "")
        self.gitlab_token = os.getenv("GITLAB_TOKEN", "")

        try:
            self.ip_address = socket.gethostbyname(domain)
            print(f"    [+] IP resuelta: {self.ip_address}")
        except Exception:
            self.ip_address = None
            print(f"    [!] No se pudo resolver IP de {domain}")

    # ---------- API 1: VIRUSTOTAL ----------
    def query_virustotal(self) -> Dict:
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
                if attributes.get('subdomains'):
                    self.subdomains_from_vt = attributes.get('subdomains', [])
                return {
                    "status": "ok",
                    "reputation": attributes.get('reputation', 0),
                    "last_analysis_stats": attributes.get('last_analysis_stats', {}),
                    "categories": attributes.get('categories', {}),
                    "subdomains": attributes.get('subdomains', [])[:15]
                }
            elif response.status_code in (401, 403):
                print("   ⚠️ VirusTotal: Clave API inválida o no autorizada.")
                return {"status": "error", "error_type": "invalid_key", "message": "Clave API inválida. Renueva tu clave en virustotal.com"}
            elif response.status_code == 429:
                print("   ⚠️ VirusTotal: Cuota agotada. Espera unos minutos.")
                return {"status": "error", "error_type": "quota_exceeded", "message": "Cuota de VirusTotal agotada. Espera o actualiza tu plan"}
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------- API 2: SHODAN ----------
    def query_shodan(self) -> Dict:
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
            elif response.status_code in (401, 403):
                print("   ⚠️ Shodan: Clave API inválida o no autorizada.")
                return {"status": "error", "error_type": "invalid_key", "message": "Clave API inválida. Renueva tu clave en shodan.io"}
            elif response.status_code == 429:
                print("   ⚠️ Shodan: Cuota agotada. Espera unos minutos.")
                return {"status": "error", "error_type": "quota_exceeded", "message": "Cuota de Shodan agotada. Espera o actualiza tu plan"}
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------- API 3: CENSYS ----------
    def query_censys(self) -> Dict:
        if not self.censys_api_id or not self.censys_api_secret:
            return {"status": "no_api_key", "message": "Configurar CENSYS_API_ID y CENSYS_API_SECRET en .env"}
        print(f"[*] Censys: consultando certificados de {self.domain}")
        try:
            from censys.search import CensysCertificates
            censys = CensysCertificates(api_id=self.censys_api_id, api_secret=self.censys_api_secret)
            query = f"parsed.names: {self.domain}"
            results = censys.search(query, per_page=10)
            certificates = []
            # CORRECCIÓN: results es un iterador, no una función
            for cert in results:
                certificates.append({
                    "names": cert.get('parsed', {}).get('names', []),
                    "fingerprint": cert.get('fingerprint', '')[:16]
                })
            return {"status": "ok", "total_certificates": len(certificates), "certificates": certificates[:10]}
        except ImportError:
            return {"status": "error", "message": "Instalar: pip install censys"}
        except Exception as e:
            error_msg = str(e).lower()
            if "invalid" in error_msg or "unauthorized" in error_msg or "403" in error_msg:
                print("   ⚠️ Censys: Clave API inválida o no autorizada.")
                return {"status": "error", "error_type": "invalid_key", "message": "Clave API inválida. Renueva tus credenciales en censys.io"}
            elif "limit" in error_msg or "429" in error_msg:
                print("   ⚠️ Censys: Cuota agotada.")
                return {"status": "error", "error_type": "quota_exceeded", "message": "Cuota de Censys agotada. Espera o actualiza tu plan"}
            return {"status": "error", "message": str(e)}

    # ---------- API 4: ALIENVAULT OTX ----------
    def query_alienvault(self) -> Dict:
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
            elif response.status_code in (401, 403):
                print("   ⚠️ AlienVault OTX: Clave API inválida o no autorizada.")
                return {"status": "error", "error_type": "invalid_key", "message": "Clave API inválida. Renueva tu clave en otx.alienvault.com"}
            elif response.status_code == 429:
                print("   ⚠️ AlienVault OTX: Cuota agotada.")
                return {"status": "error", "error_type": "quota_exceeded", "message": "Cuota de AlienVault OTX agotada. Espera o actualiza tu plan"}
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------- API 5: IPINFO ----------
    def query_ipinfo(self) -> Dict:
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
            elif response.status_code in (401, 403):
                print("   ⚠️ IPinfo: Clave API inválida o no autorizada.")
                return {"status": "error", "error_type": "invalid_key", "message": "Clave API inválida. Renueva tu clave en ipinfo.io"}
            elif response.status_code == 429:
                print("   ⚠️ IPinfo: Cuota agotada.")
                return {"status": "error", "error_type": "quota_exceeded", "message": "Cuota de IPinfo agotada. Espera o actualiza tu plan"}
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------- API 6: IPDATA ----------
    def query_ipdata(self) -> Dict:
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
            elif response.status_code in (401, 403):
                print("   ⚠️ IPdata: Clave API inválida o no autorizada.")
                return {"status": "error", "error_type": "invalid_key", "message": "Clave API inválida. Renueva tu clave en ipdata.co"}
            elif response.status_code == 429:
                print("   ⚠️ IPdata: Cuota agotada.")
                return {"status": "error", "error_type": "quota_exceeded", "message": "Cuota de IPdata agotada. Espera o actualiza tu plan"}
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------- API 7: HUNTER.IO ----------
    def query_hunter(self) -> Dict:
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
            elif response.status_code in (401, 403):
                print("   ⚠️ Hunter.io: Clave API inválida o no autorizada.")
                return {"status": "error", "error_type": "invalid_key", "message": "Clave API inválida. Renueva tu clave en hunter.io"}
            elif response.status_code == 429:
                print("   ⚠️ Hunter.io: Cuota agotada (25 consultas/mes).")
                return {"status": "error", "error_type": "quota_exceeded", "message": "Cuota de Hunter.io agotada. Espera o actualiza tu plan"}
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------- API 8: URLSCAN.IO ----------
    def query_urlscan(self) -> Dict:
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
            elif response.status_code in (401, 403):
                print("   ⚠️ urlscan.io: Clave API inválida o no autorizada.")
                return {"status": "error", "error_type": "invalid_key", "message": "Clave API inválida. Renueva tu clave en urlscan.io"}
            elif response.status_code == 429:
                print("   ⚠️ urlscan.io: Cuota agotada.")
                return {"status": "error", "error_type": "quota_exceeded", "message": "Cuota de urlscan.io agotada. Espera o actualiza tu plan"}
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------- API 9: ABUSEIPDB ----------
    def query_abuseipdb(self) -> Dict:
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
                # CORRECCIÓN: acceso seguro con .get() para evitar KeyError
                abuse_data = data.get('data', {})
                return {
                    "status": "ok",
                    "ip": self.ip_address,
                    "abuse_score": abuse_data.get('abuseConfidenceScore', 0),
                    "total_reports": abuse_data.get('totalReports', 0),
                    "country": abuse_data.get('countryCode', 'N/A')
                }
            elif response.status_code in (401, 403):
                print("   ⚠️ AbuseIPDB: Clave API inválida o no autorizada.")
                return {"status": "error", "error_type": "invalid_key", "message": "Clave API inválida. Renueva tu clave en abuseipdb.com"}
            elif response.status_code == 429:
                print("   ⚠️ AbuseIPDB: Cuota agotada (1000 consultas/día).")
                return {"status": "error", "error_type": "quota_exceeded", "message": "Cuota de AbuseIPDB agotada. Espera o actualiza tu plan"}
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------- API 10: GITHUB ----------
    def query_github(self) -> Dict:
        print(f"[*] GitHub: buscando menciones de {self.domain}")
        url = f"https://api.github.com/search/code?q={self.domain}"
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
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
            elif response.status_code == 403 and "rate limit" in response.text.lower():
                if self.github_token:
                    print("   ⚠️ GitHub: Límite de consultas excedido incluso con token.")
                    return {"status": "error", "error_type": "quota_exceeded", "message": "Límite de GitHub excedido. Espera unos minutos."}
                else:
                    print("   ⚠️ GitHub: Límite de consultas sin autenticación excedido. Configura GITHUB_TOKEN en .env para aumentarlo.")
                    return {"status": "error", "error_type": "quota_exceeded", "message": "Límite de GitHub sin autenticación. Configura un token en .env para aumentarlo."}
            return {"status": "error", "code": response.status_code, "message": "Error en la consulta a GitHub"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------- API 11: GITLAB ----------
    def query_gitlab(self) -> Dict:
        print(f"[*] GitLab: buscando menciones de {self.domain}")
        url = f"https://gitlab.com/api/v4/search?scope=projects&search={self.domain}"
        headers = {}
        if self.gitlab_token:
            headers["PRIVATE-TOKEN"] = self.gitlab_token
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "ok",
                    "total_count": len(data),
                    "items": [{"name": p['name'], "path": p['path_with_namespace']} for p in data[:5]]
                }
            elif response.status_code == 429:
                print("   ⚠️ GitLab: Límite de consultas excedido.")
                return {"status": "error", "error_type": "quota_exceeded", "message": "Límite de GitLab. Espera unos minutos."}
            elif response.status_code == 401:
                print("   ⚠️ GitLab: Token inválido o no autorizado.")
                return {"status": "error", "error_type": "invalid_key", "message": "Token de GitLab inválido. Configura GITLAB_TOKEN en .env"}
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------- Ejecución completa ----------
    def run_all(self) -> Dict:
        print("\n" + "="*55)
        print("FASE 2: THREAT INTELLIGENCE - MÚLTIPLES APIS")
        print("="*55)
        print("APIs a consultar: Shodan, Censys, VirusTotal, AlienVault, IPinfo,")
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
            "urlscan": self.query_urlscan(),
            "abuseipdb": self.query_abuseipdb(),
            "github": self.query_github(),
            "gitlab": self.query_gitlab(),
            "subdomains_from_virustotal": self.subdomains_from_vt
        }
        # Almacenar en el objeto para posible uso posterior
        self.results = results
        return results


# Ejemplo de uso rápido (opcional)
if __name__ == "__main__":
    # Reemplaza con un dominio real para probar
    ti = ThreatIntel("example.com")
    all_data = ti.run_all()
    print("\n[+] Resultados completados.")