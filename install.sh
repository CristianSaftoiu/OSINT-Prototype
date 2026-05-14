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
    echo "⚠️  Subfinder no está instalado. Ejecuta: brew install subfinder (macOS) o instálalo manualmente."
fi

echo "✅ Instalación completada!"
echo "📌 Para ejecutar: source venv/bin/activate && python main.py"
