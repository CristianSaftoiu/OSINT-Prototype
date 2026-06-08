
---

## 📄 5. `install.sh` (script de instalación automática para macOS/Linux)

```bash
#!/bin/bash
# Script de instalación automática para macOS/Linux

echo "🔍 Instalando OSINT Prototype..."

# Crear entorno virtual
python3 -m venv venv

# Activar entorno virtual
source venv/bin/activate

# Instalar dependencias
pip install --upgrade pip
pip install -r requirements.txt

# Copiar archivo de ejemplo .env
if [ ! -f .env ]; then
    cp .env.example .env
    echo "⚠️  Archivo .env creado. Añade tus API keys manualmente."
fi

# Verificar Subfinder
if ! command -v subfinder &> /dev/null; then
    echo "⚠️  Subfinder no está instalado. Instálalo con: brew install subfinder (macOS) o desde https://github.com/projectdiscovery/subfinder"
fi

# Verificar Tor
if ! command -v tor &> /dev/null; then
    echo "⚠️  Tor no está instalado. La dark web no funcionará. Instálalo con: brew install tor (macOS) o sudo apt install tor (Linux)"
fi

# Verificar Docker
if ! command -v docker &> /dev/null; then
    echo "⚠️  Docker no está instalado. El fingerprinting no funcionará. Descárgalo de https://www.docker.com/"
fi

echo "✅ Instalación completada!"
echo "📌 Para ejecutar: source venv/bin/activate && python main.py"