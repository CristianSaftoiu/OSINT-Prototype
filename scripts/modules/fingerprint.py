#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de fingerprinting usando wappalyzer-next dentro de Docker.
Busca el directorio wappalyzer-next en varias ubicaciones relativas al proyecto.
"""

import subprocess
import json
import os
from typing import List, Dict

class Fingerprinter:
    def __init__(self, wappalyzer_dir: str = None):
        """
        Si no se especifica wappalyzer_dir, se busca automáticamente en:
        - scripts/wappalyzer-next
        - wappalyzer-next (en la raíz del proyecto)
        """
        if wappalyzer_dir is None:
            base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            posibles = [
                os.path.join(base, 'scripts', 'wappalyzer-next'),
                os.path.join(base, 'wappalyzer-next'),
            ]
            encontrado = None
            for p in posibles:
                if os.path.isdir(p):
                    encontrado = p
                    break
            if encontrado is None:
                raise FileNotFoundError(
                    "No se encontró el directorio 'wappalyzer-next'. Debes clonarlo en 'scripts/wappalyzer-next' (o en la raíz) y ejecutar 'docker compose build' dentro.\n"
                    "Puedes clonarlo con:\n"
                    "  git clone https://github.com/s0md3v/wappalyzer-next.git scripts/wappalyzer-next\n"
                    "  cd scripts/wappalyzer-next && docker compose build"
                )
            self.wappalyzer_dir = encontrado
        else:
            self.wappalyzer_dir = wappalyzer_dir

        if not os.path.isdir(self.wappalyzer_dir):
            raise FileNotFoundError(f"El directorio {self.wappalyzer_dir} no existe.")

    def scan(self, urls: List[str]) -> Dict:
        results = []
        total_techs = 0

        # Filtrar URLs no relevantes (APIs, apps, etc.)
        exclude_patterns = ['api.', 'app-', 'devel-', 'k8s', 'cdn.', 'static.', 'maptiles.', 'ocpi.', 'hubject-', 'engine.', 'tileserver', 'admin.', 'login.', 'flutter', 'assets', 'test2-', 'ww1.', 'ww7.', 'mx10.', 'hostmaster.', 'comune.']
        urls_filtradas = [u for u in urls if not any(p in u for p in exclude_patterns)]

        print(f"   [*] Analizando {len(urls_filtradas)} URLs (de {len(urls)} totales)...")

        for url in urls_filtradas:
            try:
                cmd = ['docker', 'compose', 'run', '--rm', 'wappalyzer', '-i', url, '-oJ']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=self.wappalyzer_dir)

                if result.returncode != 0:
                    continue

                output = result.stdout
                json_line = None
                for line in output.splitlines():
                    if line.strip().startswith('{'):
                        json_line = line.strip()
                        break

                if not json_line:
                    continue

                data = json.loads(json_line)
                if isinstance(data, dict) and len(data) == 1:
                    tech_dict = list(data.values())[0]
                else:
                    tech_dict = data

                for tech_name, tech_info in tech_dict.items():
                    version = tech_info.get('version', 'N/A')
                    if isinstance(version, list):
                        version = version[0] if version else 'N/A'
                    results.append({
                        "url": url,
                        "technology": tech_name,
                        "version": version,
                        "confidence": tech_info.get('confidence', 100)
                    })
                    total_techs += 1

            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue

        return {
            "status": "success",
            "results": results,
            "total_technologies": total_techs
        }