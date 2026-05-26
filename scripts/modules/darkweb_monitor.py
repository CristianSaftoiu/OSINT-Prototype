#!/usr/bin/env python3
# ↑ Shebang para ejecutar con Python 3

"""
Módulo de monitorización avanzada en Dark Web.
Usa osint-darkweb-pkg para buscar en 15+ motores, con respaldo en Ahmia.
Además, realiza crawling de los enlaces .onion para detectar amenazas.
Requiere Tor corriendo en 127.0.0.1:9050
"""

# ==================== IMPORTACIONES ====================
import requests               # Para hacer peticiones HTTP a través de Tor
from bs4 import BeautifulSoup # Para parsear HTML (extraer títulos, descripciones)
import json                   # (No usado directamente, pero puede ser útil para depuración)
import time                   # Para añadir timestamp a los resultados
import socket                 # Para comprobar si el puerto 9050 está abierto
import platform               # Para detectar el sistema operativo y dar instrucciones adecuadas
import re                     # Para buscar correos electrónicos y patrones en el texto
from typing import List, Dict # Para anotar tipos de datos (mejora la legibilidad)

# ==================== BIBLIOTECA MULTI-MOTOR (opcional) ====================
try:
    from osint_darkweb_pkg import get_search_results
    MULTI_ENGINE_AVAILABLE = True   # Si está instalada, activamos la búsqueda multi-motor
except ImportError:
    MULTI_ENGINE_AVAILABLE = False
    print("[!] osint-darkweb-pkg no instalado. La búsqueda multi-motor no estará disponible.")

# ==================== CLASE PRINCIPAL ====================
class DarkWebMonitor:
    """
    Clase que realiza búsquedas en la dark web (Tor) usando:
      - osint-darkweb-pkg (15+ motores) si está disponible.
      - Ahmia como respaldo.
    Luego analiza los enlaces .onion encontrados (crawling) para detectar amenazas.
    """

    def __init__(self, keyword: str):
        """
        Constructor.
        :param keyword: palabra clave a buscar (normalmente el dominio, ej: 'zunder.com')
        """
        self.keyword = keyword
        # Proxy SOCKS5h para enrutar el tráfico a través de Tor (localhost:9050)
        self.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        self.timeout = 60          # Tiempo máximo de espera para las peticiones (60 segundos)
        self.results = []          # Lista para almacenar resultados intermedios (no se usa mucho)
        self.os_name = platform.system().lower()   # 'windows', 'linux' o 'darwin' (macOS)

    # ------------------------------------------------------------
    # Método auxiliar: instrucciones para iniciar Tor según SO
    # ------------------------------------------------------------
    def _tor_instructions(self) -> str:
        """Devuelve las instrucciones para iniciar Tor según el sistema operativo."""
        if self.os_name == "windows":
            return "Inicia Tor Browser o el servicio Tor (puerto 9050)."
        elif self.os_name == "linux":
            return "Ejecuta: sudo systemctl start tor (o 'sudo service tor start')"
        else:  # macOS / Darwin
            return "Ejecuta: brew services start tor (si instalaste Tor con Homebrew)"

    # ------------------------------------------------------------
    # Verificación de Tor
    # ------------------------------------------------------------
    def check_tor(self) -> bool:
        """
        Verifica si Tor está corriendo en el puerto 9050 y puede enrutar tráfico.
        1) Comprueba que el puerto SOCKS esté abierto.
        2) Hace una petición a check.torproject.org para confirmar que el tráfico sale por Tor.
        Retorna True si Tor funciona, False en caso contrario.
        """
        # 1) Probar conexión al puerto 9050
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)                     # Timeout de 3 segundos
            if sock.connect_ex(('127.0.0.1', 9050)) != 0:   # Si devuelve !=0, el puerto no está abierto
                return False
            sock.close()
        except Exception:
            return False

        # 2) Probar que Tor realmente enruta peticiones (evita puerto abierto pero Tor muerto)
        try:
            r = requests.get('https://check.torproject.org/', proxies=self.proxies, timeout=15)
            # La página devuelve "Congratulations" si se está usando Tor
            return 'Congratulations' in r.text or r.status_code == 200
        except Exception:
            return False

    # ------------------------------------------------------------
    # Búsqueda multi-motor (si osint-darkweb-pkg está instalado)
    # ------------------------------------------------------------
    def search_multi_engine(self) -> List[Dict]:
        """
        CAPA 1: Usa osint-darkweb-pkg para buscar en 15+ motores de la dark web.
        Aplica un filtro agresivo para eliminar resultados basura (navegación, menús, etc.)
        y solo conserva enlaces .onion que contengan la keyword.
        Retorna una lista de diccionarios con 'title', 'link', 'source'.
        """
        if not MULTI_ENGINE_AVAILABLE:
            return []          # Si no está la librería, no hacemos nada
        print(f"[*] Buscando en 15+ motores...")
        try:
            resultados_raw = get_search_results(self.keyword)   # Devuelve una lista de resultados sin filtrar
            resultados_filtrados = []
            # Patrones para excluir resultados que no son enlaces reales (menús, botones, etc.)
            exclude_patterns = [
                '/search?', '/directory', '/advertising', '/last-added', '/contact', '/webmaster',
                'add link', 'about', 'ascending', 'descending', 'sort', 'order', 'filter',
                'language', 'submit', 'register', 'login', 'signup'
            ]
            for item in resultados_raw:
                link = item.get('link', '')
                title = item.get('title', '').lower()
                # Sólo nos interesan enlaces .onion
                if '.onion' not in link:
                    continue
                # Verificar si el título o link contiene algún patrón excluido
                skip = False
                for pattern in exclude_patterns:
                    if pattern in link.lower() or pattern in title:
                        skip = True
                        break
                if skip:
                    continue
                # Para ser relevante, la keyword debe aparecer en el título o en el enlace
                keyword_lower = self.keyword.lower()
                if keyword_lower in title or keyword_lower in link:
                    resultados_filtrados.append({
                        "title": item.get('title', 'N/A')[:100],   # Limitar a 100 caracteres
                        "link": link,
                        "source": "multi_engine"
                    })
            print(f"[✓] Relevantes: {len(resultados_filtrados)} (de {len(resultados_raw)} totales)")
            return resultados_filtrados
        except Exception as e:
            print(f"[!] Error: {e}")
            return []

    # ------------------------------------------------------------
    # Búsqueda de respaldo en Ahmia
    # ------------------------------------------------------------
    def search_ahmia(self) -> List[Dict]:
        """
        CAPA de respaldo: Busca exclusivamente en el motor Ahmia (ahmia.fi).
        Se usa si la búsqueda multi-motor no devuelve resultados o falla.
        Extrae enlaces .onion de los divs con clase 'result'.
        Retorna lista de diccionarios con 'title', 'link', 'description', 'source'.
        """
        print(f"[*] Buscando en Ahmia (respaldo)...")
        url = f"https://ahmia.fi/search/?q={self.keyword}"
        results = []
        try:
            r = requests.get(url, proxies=self.proxies, timeout=self.timeout)
            if r.status_code != 200:
                return [{"error": f"HTTP {r.status_code}"}]
            soup = BeautifulSoup(r.text, 'html.parser')
            # Cada resultado de Ahmia está dentro de un div con clase 'result'
            for result in soup.select('div.result'):
                link_elem = result.select_one('a.result-link')
                if not link_elem:
                    continue
                link = link_elem.get('href', '')
                if '.onion' not in link:
                    continue
                title = link_elem.get_text(strip=True) or link.split('/')[-1] or link[:50]
                desc_elem = result.select_one('p.result-description')
                description = desc_elem.get_text(strip=True) if desc_elem else ''
                results.append({
                    "title": title[:100],
                    "link": link,
                    "description": description[:200],
                    "source": "ahmia"
                })
            print(f"[✓] Ahmia: {len(results)} enlaces .onion encontrados.")
            return results
        except Exception as e:
            print(f"[!] Error en Ahmia: {e}")
            return [{"error": str(e)}]

    # ------------------------------------------------------------
    # Crawling y análisis de amenazas
    # ------------------------------------------------------------
    def crawl_onion_links(self, links: List[str], max_links: int = 10) -> List[Dict]:
        """
        CAPA 2: Dada una lista de URLs .onion, descarga cada página (a través de Tor),
        extrae el título, busca correos electrónicos y palabras clave de amenaza,
        y asigna un nivel de riesgo (HIGH, MEDIUM, LOW).
        :param links: lista de enlaces .onion
        :param max_links: número máximo de enlaces a analizar (para no sobrecargar)
        :return: lista de diccionarios con el análisis de cada enlace.
        """
        analyzed = []
        # Palabras que indican posible amenaza (fuga, credenciales, hack, etc.)
        threat_keywords = ["leak", "breach", "credential", "password", "database", "dump",
                           "hack", "exploit", "zunder", "filtración", "credenciales"]

        for idx, link in enumerate(links[:max_links]):
            print(f"[*] Analizando {idx+1}/{min(len(links), max_links)}: {link}")
            result = {
                "url": link,
                "title": "N/A",
                "emails": [],
                "keywords_found": [],
                "threat_level": "LOW",
                "error": None
            }
            try:
                # Descargar la página .onion usando el proxy SOCKS5 de Tor
                r = requests.get(link, proxies=self.proxies, timeout=30)
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, 'html.parser')
                    # Extraer título de la página
                    if soup.title and soup.title.string:
                        result["title"] = soup.title.string.strip()[:100]
                    # Buscar direcciones de correo electrónico con expresión regular
                    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r.text)
                    result["emails"] = list(set(emails))[:5]   # Hasta 5 emails únicos
                    # Buscar palabras clave de amenaza en el texto de la página
                    text_lower = r.text.lower()
                    found = [kw for kw in threat_keywords if kw in text_lower]
                    result["keywords_found"] = found
                    # Clasificación del nivel de amenaza
                    if len(found) >= 2:
                        result["threat_level"] = "HIGH"
                    elif len(found) == 1:
                        result["threat_level"] = "MEDIUM"
                else:
                    result["error"] = f"HTTP {r.status_code}"
            except Exception as e:
                result["error"] = str(e)
            analyzed.append(result)
        return analyzed

    # ------------------------------------------------------------
    # Método principal que orquesta todo el flujo
    # ------------------------------------------------------------
    def run_all(self) -> Dict:
        """
        Ejecuta la monitorización completa:
          1) Verifica Tor.
          2) Intenta búsqueda multi-motor (si disponible).
          3) Si no hay resultados, usa Ahmia como respaldo.
          4) Elimina duplicados.
          5) Realiza crawling y análisis de amenazas sobre los primeros enlaces.
        Retorna un diccionario con el estado, la palabra clave, el total de enlaces,
        los resultados brutos y los análisis de amenazas.
        """
        print(f"[*] Conectando a la red Tor...")
        if not self.check_tor():
            return {
                "status": "error",
                "message": f"Tor no está corriendo. {self._tor_instructions()}",
                "results": []
            }
        print("[✓] Tor conectado.")

        # Fase 1: búsqueda multi-motor (si está disponible)
        resultados = self.search_multi_engine()
        if not resultados:
            print("[*] Sin resultados relevantes. Probando Ahmia...")
            resultados = self.search_ahmia()   # Respaldo

        # Eliminar duplicados usando un diccionario clave = link
        unicos = {}
        for r in resultados:
            link = r.get('link')
            if link and link not in unicos:
                unicos[link] = r
        resultados_limpios = list(unicos.values())

        # Fase 2: crawling y análisis de amenazas (solo si hay enlaces, máximo 5 para no saturar)
        analyzed_links = []
        if resultados_limpios:
            onion_urls = [r["link"] for r in resultados_limpios if r.get("link") and ".onion" in r["link"]]
            if onion_urls:
                analyzed_links = self.crawl_onion_links(onion_urls, max_links=5)

        # Devolver todos los datos estructurados
        return {
            "status": "success",
            "keyword": self.keyword,
            "total_links_found": len(resultados_limpios),
            "raw_results": resultados_limpios,
            "analyzed_threats": analyzed_links,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }