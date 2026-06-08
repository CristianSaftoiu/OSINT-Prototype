# 🔍 OSINT Prototype - Passive Asset Discovery Tool (con monitorización en Dark Web)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📌 Descripción

Herramienta OSINT para el descubrimiento pasivo de activos expuestos en Internet, incluyendo búsquedas en la red Tor (dark web), fingerprinting tecnológico y análisis de vulnerabilidades (CVEs). Realiza consultas exclusivamente a fuentes públicas indexadas, **sin interacción directa** con los sistemas objetivo.

### 🎯 ¿Para qué sirve?

-- Descubrimiento de subdominios, registros DNS y WHOIS.
- Verificación de actividad de máquinas mediante ICMP y TCP.
- Integración con 13+ APIs de threat intelligence (VirusTotal, Shodan, Hunter, etc.).
- Monitorización en dark web (Ahmia, con soporte multi-motor opcional).
- Fingerprinting tecnológico (detección de versiones de software, frameworks, etc.) usando wappalyzer-next (Docker).
- Búsqueda de vulnerabilidades (CVEs) asociadas a tecnologías detectadas (NVD API).
- Detección de exploits públicos (Exploit-DB).
- Generación de informes en JSON, CSV y Markdown.

### 📖 Uso de la Dark Web

Durante la ejecución, se te preguntará:
   ¿Deseas realizar la búsqueda en la Dark Web? (s/n):
Si respondes s y Tor está activo, el prototipo buscará en el motor Ahmia (.onion) los enlaces relacionados con el dominio.
Los resultados (título y enlace .onion) se añadirán al informe Markdown.
Si Tor no está corriendo, se mostrará un mensaje de error y se omitirá la búsqueda.

### ⚠️ Importante

> **La búsqueda en dark web requiere Tor y debe usarse únicamente con fines educativos y de investigación autorizada. No interactúa con contenido ilegal.**

---

## 🚀 Instalación rápida

### 1. Clonar el repositorio

```bash
git clone https://github.com/CristianSaftoiu/OSINT-Prototype.git
cd OSINT-Prototype
```
### 2. Crear entorno virtual

```bash
python3 -m venv venv
source venv/bin/activate   # En Windows: venv\Scripts\activate
```

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 4. Configurar API keys (opcional)

```bash
cp .env.example .env
nano .env   # Añade tus claves (Shodan, VirusTotal, Hunter, etc.)
```

### 5. Instalar Docker y wappalyzer-next (para fingerprinting)

```bash
git clone https://github.com/s0md3v/wappalyzer-next.git scripts/wappalyzer-next
cd scripts/wappalyzer-next
docker compose build
cd ../..
```

### 6. Instalar Exploit-DB (opcional, para búsqueda de exploits)

```bash
# macOS
brew install exploitdb

# Linux
sudo apt install exploitdb
```

### 7. Instalar y ejecutar Tor (para la dark web)

```bash
# macOS
brew install tor
brew services start tor

# Linux (Debian/Ubuntu)
sudo apt install tor
sudo systemctl start tor

# Verificar que Tor está corriendo
brew services list | grep tor   # o systemctl status tor
```

### 8. Ejecutar 

```bash
python main.py
```
