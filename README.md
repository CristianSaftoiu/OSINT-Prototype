# 🔍 OSINT Prototype

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://www.docker.com/)

## 📌 Descripción

Herramienta OSINT (Open Source Intelligence) para el descubrimiento de activos expuestos en Internet, incluyendo búsquedas en la red Tor (dark web), fingerprinting tecnológico (detección de versiones de software) y análisis de vulnerabilidades (CVEs) con búsqueda de exploits públicos.

Realiza consultas exclusivamente a fuentes públicas indexadas, **sin interacción directa** con los sistemas objetivo.

### 🎯 Funcionalidades principales

- Descubrimiento de subdominios (crt.sh, Subfinder, BufferOver, DNS, WHOIS)
- Verificación de actividad de máquinas mediante ICMP y TCP/80
- Integración con 13 APIs de threat intelligence (VirusTotal, Shodan, Hunter, etc.)
- Fingerprinting tecnológico (detección de versiones) usando wappalyzer-next (requiere Docker)
- Búsqueda de vulnerabilidades (CVEs) asociadas a tecnologías detectadas (NVD API)
- Detección de exploits públicos (Exploit-DB vía searchsploit)
- Monitorización en dark web (Ahmia + crawling) a través de Tor
- Generación de informes en SON, CSV y Markdown (con nombre del dominio y timestamp)

### ⚠️ Importante

> Su uso es exclusivamente para auditorías defensivas y fines educativos.

> El fingerprinting requiere Docker instalado y funcionando. La dark web requiere Tor activo.

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
