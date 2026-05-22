#!/usr/bin/env python3
"""
Módulo de monitorización en Dark Web usando Ahmia (motor .onion estable)
Requiere Tor corriendo en 127.0.0.1:9050
"""

import requests
from bs4 import BeautifulSoup
import json
import time
from typing import List, Dict

class DarkWebMonitor:
    def __init__(self, keyword: str):
        self.keyword = keyword
        self.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        self.timeout = 60
        self.results = []

    def check_tor(self) -> bool:
        """Verifica si Tor está accesible en el puerto 9050"""
        try:
            test_url = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/"
            r = requests.get(test_url, proxies=self.proxies, timeout=15)
            return r.status_code == 200
        except:
            return False

    def search_ahmia(self) -> List[Dict]:
        """Busca en Ahmia y devuelve lista de resultados (título, enlace, descripción)"""
        url = f"https://ahmia.fi/search/?q={self.keyword}"
        results = []
        try:
            r = requests.get(url, proxies=self.proxies, timeout=self.timeout)
            if r.status_code != 200:
                return [{"error": f"HTTP {r.status_code}"}]
            
            soup = BeautifulSoup(r.text, 'html.parser')
            for result in soup.select('div.result'):
                title_elem = result.select_one('a.result-link')
                desc_elem = result.select_one('p.result-description')
                if title_elem:
                    link = title_elem.get('href', '')
                    title = title_elem.get_text(strip=True)
                    description = desc_elem.get_text(strip=True) if desc_elem else ''
                    if '.onion' in link:
                        results.append({
                            "title": title,
                            "link": link,
                            "description": description[:200]
                        })
            return results
        except Exception as e:
            return [{"error": str(e)}]

    def run_all(self) -> Dict:
        """Ejecuta la monitorización y devuelve resultados estructurados"""
        print(f"[*] Conectando a la red Tor...")
        if not self.check_tor():
            return {
                "status": "error",
                "message": "Tor no está corriendo. Inícialo con: brew services start tor",
                "results": []
            }
        print("[✓] Tor conectado. Buscando en Ahmia...")
        resultados = self.search_ahmia()
        return {
            "status": "success",
            "keyword": self.keyword,
            "total": len(resultados),
            "results": resultados,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }