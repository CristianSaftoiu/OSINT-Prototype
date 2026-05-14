"""
Módulo de verificación de actividad de máquinas
Métodos: ICMP (ping) y TCP (conexión a puerto 80)
"""

import subprocess
import socket
import platform
from typing import Dict, List, Tuple

class ActiveChecker:
    """
    Clase para verificar si una máquina está activa mediante:
    1. ICMP (ping) - Envía ICMP Echo Request, espera ICMP Echo Reply
    2. TCP - Conexión a puerto 80/TCP con handshake SYN/SYN+ACK
    """
    
    def __init__(self):
        self.sistema = platform.system().lower()
        self.resultados = {}
    
    def check_icmp(self, host: str) -> Tuple[bool, str]:
        """
        Envía petición ICMP (ping) y espera respuesta ICMP-0
        Retorna: (activo, mensaje)
        """
        try:
            # Parámetros según sistema operativo
            if self.sistema == "windows":
                param = ['ping', '-n', '1', '-w', '2000', host]
            else:  # Linux / Mac / Darwin
                param = ['ping', '-c', '1', '-W', '2', host]
            
            result = subprocess.run(
                param,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Verificar respuesta ICMP-0 (código 0 = Echo Reply)
            if result.returncode == 0:
                return (True, f"ICMP: Host {host} ACTIVO (respuesta ICMP-0 recibida)")
            else:
                return (False, f"ICMP: Host {host} no responde a ping")
                
        except subprocess.TimeoutExpired:
            return (False, f"ICMP: Timeout - {host} no responde")
        except Exception as e:
            return (False, f"ICMP: Error - {str(e)}")
    
    def check_tcp(self, host: str, port: int = 80, timeout: int = 3) -> Tuple[bool, str]:
        """
        Establece conexión TCP al puerto especificado (por defecto 80/TCP)
        Envía SYN, espera SYN+ACK o RST
        Retorna: (activo, mensaje)
        """
        try:
            # Crear socket TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Intentar conexión (envía SYN)
            resultado = sock.connect_ex((host, port))
            
            # Cerrar socket
            sock.close()
            
            # Si resultado == 0, conexión exitosa (SYN+ACK recibido)
            if resultado == 0:
                return (True, f"TCP/{port}: Host {host} ACTIVO (SYN+ACK recibido)")
            else:
                return (False, f"TCP/{port}: Host {host} no responde en puerto {port}")
                
        except socket.timeout:
            return (False, f"TCP/{port}: Timeout - {host} no responde")
        except ConnectionRefusedError:
            # RST recibido -> máquina activa pero puerto cerrado
            return (True, f"TCP/{port}: Host {host} ACTIVO (RST recibido - puerto {port} cerrado)")
        except Exception as e:
            return (False, f"TCP/{port}: Error - {str(e)}")
    
    def check_host(self, host: str, tcp_port: int = 80) -> Dict:
        """
        Verifica actividad de un host combinando ICMP y TCP (fallback)
        Estrategia:
        1. Intentar ICMP primero
        2. Si ICMP falla, intentar TCP al puerto 80
        3. Si TCP falla, considerar "NO ACTIVA"
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
                estado = "NO ACTIVA (o no detectable)"
                metodo = "ICMP+TCP"
                mensaje = f"ICMP: no respuesta | TCP: no respuesta"
        
        resultado = {
            "host": host,
            "estado": estado,
            "metodo_deteccion": metodo,
            "detalle": mensaje
        }
        
        print(f"    [{'✓' if 'ACTIVA' in estado else '✗'}] {host} -> {estado}")
        
        return resultado
    
    def check_multiple_hosts(self, hosts: List[str], tcp_port: int = 80) -> List[Dict]:
        """Verifica múltiples hosts y muestra el resultado real"""
        resultados = []
        print("\n    Resultados de verificación:")
        print("    " + "-" * 40)
        
        for host in hosts:
            if host:
                resultado = self.check_host(host.strip(), tcp_port)
                resultados.append(resultado)
                
                # Mostrar resultado con icono correcto
                if resultado['estado'] == "ACTIVA":
                    print(f"    [✓] {host} -> ACTIVA (detectada por {resultado['metodo_deteccion']})")
                else:
                    print(f"    [✗] {host} -> NO ACTIVA (no responde a ICMP ni TCP/80)")
        
        return resultados
    
    def generar_resumen(self, resultados: List[Dict]) -> Dict:
        """Genera estadísticas de los resultados"""
        total = len(resultados)
        
        # Contar SOLO los que son EXACTAMENTE "ACTIVA"
        activos = sum(1 for r in resultados if r.get('estado') == "ACTIVA")
        no_activos = total - activos
        
        # Contar métodos de detección solo para los ACTIVOS
        activos_icmp = sum(1 for r in resultados if r.get('estado') == "ACTIVA" and r.get('metodo_deteccion') == "ICMP")
        activos_tcp = sum(1 for r in resultados if r.get('estado') == "ACTIVA" and r.get('metodo_deteccion') == "TCP")
        
        return {
            "total_hosts": total,
            "activos": activos,
            "no_activos": no_activos,
            "detectados_por_icmp": activos_icmp,
            "detectados_por_tcp": activos_tcp,
            "porcentaje_actividad": round((activos / total) * 100, 2) if total > 0 else 0
        }



# Prueba independiente del módulo
if __name__ == "__main__":
    checker = ActiveChecker()
    
    # Pruebas con diferentes hosts
    test_hosts = [
        "google.com",      # Debería estar ACTIVO
        "8.8.8.8",         # DNS Google, ACTIVO
        "192.168.1.1",     # Posible router, puede no responder
        "zunder.com"       # Dominio del proyecto
    ]
    
    print("=" * 60)
    print("PRUEBA DEL MÓDULO DE VERIFICACIÓN DE ACTIVIDAD")
    print("=" * 60)
    
    resultados = checker.check_multiple_hosts(test_hosts)
    
    print("\n" + "=" * 60)
    print("RESUMEN DE RESULTADOS")
    print("=" * 60)
    
    resumen = checker.generar_resumen(resultados)
    print(f"  Total hosts analizados: {resumen['total_hosts']}")
    print(f"  Hosts ACTIVOS: {resumen['activos']}")
    print(f"  Hosts NO ACTIVOS: {resumen['no_activos']}")
    print(f"  Detectados por ICMP: {resumen['detectados_por_icmp']}")
    print(f"  Detectados por TCP: {resumen['detectados_por_tcp']}")
    print(f"  Porcentaje de actividad: {resumen['porcentaje_actividad']}%")