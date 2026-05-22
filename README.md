# 🔍 OSINT Prototype - Passive Asset Discovery Tool (con monitorización en Dark Web)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📌 Descripción

Herramienta OSINT (Open Source Intelligence) para el descubrimiento pasivo de activos expuestos en Internet, incluyendo búsquedas en la red Tor (dark web). Realiza consultas exclusivamente a fuentes públicas indexadas, sin interacción directa con los sistemas objetivo.

### 🎯 ¿Para qué sirve?

- Descubrir subdominios, registros DNS y WHOIS.
- Identificar tecnologías y servicios expuestos.
- Encontrar correos electrónicos corporativos.
- Verificar reputación de dominios e IPs.
- Detectar máquinas activas mediante ICMP y TCP.
- Buscar en la dark web (a través de Ahmia) menciones o enlaces relacionados con el dominio.
- Generar informes en JSON, CSV y Markdown.

### 📖 Uso de la Dark Web

Durante la ejecución, se te preguntará:
   ¿Deseas realizar la búsqueda en la Dark Web? (s/n):
Si respondes s y Tor está activo, el prototipo buscará en el motor Ahmia (.onion) los enlaces relacionados con el dominio.
Los resultados (título y enlace .onion) se añadirán al informe Markdown.
Si Tor no está corriendo, se mostrará un mensaje de error y se omitirá la búsqueda.

### ⚠️ Importante

> **Este prototipo solo realiza consultas PASIVAS. La búsqueda en dark web requiere Tor y debe usarse únicamente con fines educativos y de investigación autorizada. No interactúa con contenido ilegal.**

---

## 🚀 Instalación rápida

### 1. Clonar el repositorio

```bash
git clone https://github.com/CristianSaftoiu/OSINT-Prototype.git
cd OSINT-Prototype
```
### 1. Crear entorno virtual

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

### 5. Instalar y ejecutar Tor (para la dark web)

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

### 6. Ejecutar 

```bash
python main.py
```
