#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de verificación de actividad de máquinas.
Métodos: ICMP (ping) y TCP (conexión a puerto 80).
"""

# ==================== IMPORTACIONES ====================
import subprocess   # Para ejecutar el comando ping del sistema operativo
import socket       # Para intentar conexiones TCP (connect_ex)
import platform     # Para detectar el sistema operativo y ajustar los parámetros de ping
from typing import Dict, List, Tuple  # Para anotar tipos

# ==================== CLASE PRINCIPAL ====================
class ActiveChecker:
    """
    Clase para verificar si una máquina (host) está activa mediante:
    1. ICMP (ping) - Envía ICMP Echo Request, espera ICMP Echo Reply.
    2. TCP - Conexión a puerto 80/TCP con handshake SYN/SYN+ACK.
    """
    
    def __init__(self):
        """Inicializa el detector guardando el nombre del sistema operativo."""
        self.sistema = platform.system().lower()   # 'windows', 'linux', 'darwin' (macOS)
        self.resultados = {}                       # (no se usa intensivamente, para futura ampliación)

    # ------------------------------------------------------------
    # 1. Verificación por ICMP (ping)
    # ------------------------------------------------------------
    def check_icmp(self, host: str) -> Tuple[bool, str]:
        """
        Envía una petición ICMP Echo Request (ping) y espera respuesta ICMP Echo Reply.
        Retorna una tupla: (activo: bool, mensaje: str)
        """
        try:
            # Parámetros según el sistema operativo (Windows usa opciones diferentes)
            if self.sistema == "windows":
                # Windows: -n 1 (1 paquete), -w 2000 (timeout en ms)
                param = ['ping', '-n', '1', '-w', '2000', host]
            else:  # Linux / Mac / Darwin
                # Unix-like: -c 1 (1 paquete), -W 2 (timeout en segundos)
                param = ['ping', '-c', '1', '-W', '2', host]
            
            # Ejecutar el comando ping
            result = subprocess.run(
                param,
                capture_output=True,   # Captura stdout y stderr
                text=True,             # Devuelve cadenas de texto (no bytes)
                timeout=5              # Timeout total del subproceso
            )
            
            # Código de retorno 0 indica que hubo respuesta (ICMP Echo Reply)
            if result.returncode == 0:
                return (True, f"ICMP: Host {host} ACTIVO (respuesta ICMP-0 recibida)")
            else:
                return (False, f"ICMP: Host {host} no responde a ping")
                
        except subprocess.TimeoutExpired:
            return (False, f"ICMP: Timeout - {host} no responde")
        except Exception as e:
            return (False, f"ICMP: Error - {str(e)}")

    # ------------------------------------------------------------
    # 2. Verificación por TCP (conexión al puerto 80)
    # ------------------------------------------------------------
    def check_tcp(self, host: str, port: int = 80, timeout: int = 3) -> Tuple[bool, str]:
        """
        Intenta establecer una conexión TCP al puerto especificado.
        Envía SYN, espera SYN+ACK (conexión exitosa) o RST (puerto cerrado).
        Retorna: (activo: bool, mensaje: str)
        """
        try:
            # Crear un socket TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)       # Timeout para la operación de conexión
            
            # connect_ex devuelve 0 si la conexión fue exitosa (SYN+ACK recibido)
            resultado = sock.connect_ex((host, port))
            
            # Cerrar el socket (libera recursos)
            sock.close()
            
            # Si resultado == 0, el host respondió al SYN con SYN+ACK -> activo
            if resultado == 0:
                return (True, f"TCP/{port}: Host {host} ACTIVO (SYN+ACK recibido)")
            else:
                return (False, f"TCP/{port}: Host {host} no responde en puerto {port}")
                
        except socket.timeout:
            # Timeout: no hubo respuesta al SYN
            return (False, f"TCP/{port}: Timeout - {host} no responde")
        except ConnectionRefusedError:
            # RST recibido: el host está activo pero el puerto está cerrado
            return (True, f"TCP/{port}: Host {host} ACTIVO (RST recibido - puerto {port} cerrado)")
        except Exception as e:
            return (False, f"TCP/{port}: Error - {str(e)}")

    # ------------------------------------------------------------
    # 3. Verificación combinada (ICMP + TCP fallback)
    # ------------------------------------------------------------
    def check_host(self, host: str, tcp_port: int = 80) -> Dict:
        """
        Verifica actividad de un host combinando ICMP y TCP (fallback).
        Estrategia:
          1. Intentar ICMP primero.
          2. Si ICMP falla, intentar TCP al puerto 80.
          3. Si también falla, considerar "NO ACTIVA (o no detectable)".
        Retorna un diccionario con host, estado, método de detección y detalle.
        """
        print(f"    [*] Verificando actividad de: {host}")
        
        # Primer intento: ICMP
        icmp_activo, icmp_msg = self.check_icmp(host)
        
        if icmp_activo:
            estado = "ACTIVA"
            metodo = "ICMP"
            mensaje = icmp_msg
        else:
            # Segundo intento: TCP (fallback)
            tcp_activo, tcp_msg = self.check_tcp(host, tcp_port)
            
            if tcp_activo:
                estado = "ACTIVA"
                metodo = "TCP"
                mensaje = tcp_msg
            else:
                # Ambos fallaron: no podemos determinar actividad
                estado = "NO ACTIVA (o no detectable)"
                metodo = "ICMP+TCP"
                mensaje = f"ICMP: no respuesta | TCP: no respuesta"
        
        # Construir resultado para este host
        resultado = {
            "host": host,
            "estado": estado,
            "metodo_deteccion": metodo,
            "detalle": mensaje
        }
        
        # Mostrar icono en consola según resultado (✓ o ✗)
        # Nota: se usa 'if "ACTIVA" in estado' porque el texto exacto puede variar
        print(f"    [{'✓' if 'ACTIVA' in estado else '✗'}] {host} -> {estado}")
        
        return resultado

    # ------------------------------------------------------------
    # 4. Verificar múltiples hosts (lote)
    # ------------------------------------------------------------
    def check_multiple_hosts(self, hosts: List[str], tcp_port: int = 80) -> List[Dict]:
        """
        Verifica una lista de hosts (dominios o IPs) y muestra el resultado.
        Retorna una lista de diccionarios con los resultados de cada host.
        """
        resultados = []
        print("\n    Resultados de verificación:")
        print("    " + "-" * 40)
        
        for host in hosts:
            if host:   # Ignorar entradas vacías
                resultado = self.check_host(host.strip(), tcp_port)
                resultados.append(resultado)
                
                # Mensaje adicional con icono y método
                if resultado['estado'] == "ACTIVA":
                    print(f"    [✓] {host} -> ACTIVA (detectada por {resultado['metodo_deteccion']})")
                else:
                    print(f"    [✗] {host} -> NO ACTIVA (no responde a ICMP ni TCP/80)")
        
        return resultados

    # ------------------------------------------------------------
    # 5. Generar resumen estadístico
    # ------------------------------------------------------------
    def generar_resumen(self, resultados: List[Dict]) -> Dict:
        """
        Analiza la lista de resultados y genera estadísticas:
          - total_hosts, activos, no_activos
          - detectados_por_icmp, detectados_por_tcp
          - porcentaje_actividad
        """
        total = len(resultados)
        
        # Contar SOLO los que tienen estado EXACTAMENTE "ACTIVA"
        activos = sum(1 for r in resultados if r.get('estado') == "ACTIVA")
        no_activos = total - activos
        
        # Entre los activos, contar cuántos fueron detectados por ICMP y cuántos por TCP
        activos_icmp = sum(1 for r in resultados 
                           if r.get('estado') == "ACTIVA" and r.get('metodo_deteccion') == "ICMP")
        activos_tcp = sum(1 for r in resultados 
                          if r.get('estado') == "ACTIVA" and r.get('metodo_deteccion') == "TCP")
        
        return {
            "total_hosts": total,
            "activos": activos,
            "no_activos": no_activos,
            "detectados_por_icmp": activos_icmp,
            "detectados_por_tcp": activos_tcp,
            "porcentaje_actividad": round((activos / total) * 100, 2) if total > 0 else 0
        }