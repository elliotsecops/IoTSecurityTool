import nmap
import re
import os
import csv
from datetime import datetime
import argparse
import concurrent.futures
import multiprocessing

# Inicializar el escáner de Nmap
nm = nmap.PortScanner()

# Caché para búsquedas en ExploitDB
exploitdb_cache = {}

# Cargar ExploitDB en un diccionario para búsquedas más rápidas
def load_exploitdb(exploitdb_path):
    exploitdb_csv = os.path.join(exploitdb_path, 'files_exploits.csv') # Archivo CSV de ExploitDB
    if not os.path.exists(exploitdb_csv):
        print("No se encontró la base de datos de ExploitDB.")
        return {}

    exploit_dict = {}
    with open(exploitdb_csv, 'r') as csvf:
        csv_reader = csv.DictReader(csvf)
        for row in csv_reader:
            exploit_dict[row['description']] = row
    return exploit_dict

# Buscar en ExploitDB usando el diccionario
def search_exploitdb(cve_id, exploit_dict):
    if cve_id in exploitdb_cache:
        return exploitdb_cache[cve_id]
    
    related_exploits = []
    for description, exploit in exploit_dict.items():
        if cve_id in description:
            related_exploits.append(exploit)
    
    exploitdb_cache[cve_id] = related_exploits
    return related_exploits

# Escanear la red en el rango dado
def scan_network(ip_range):
    print(f"Escaneando la red: {ip_range}...")
    nm.scan(hosts=ip_range, arguments='-O') # Opción -O para detección de sistema operativo
    devices = []
    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            mac_address = nm[host]['addresses']['mac']
            vendor = nm[host]['vendor'].get(mac_address, 'Unknown')
            print(f"Dispositivo encontrado: IP {host}, MAC {mac_address}, Fabricante {vendor}")
            devices.append({'ip': host, 'mac': mac_address, 'vendor': vendor})
    return devices

# Ejecutar scripts NSE para vulnerabilidades
def detect_vulnerabilities(ip, exploit_dict):
    print(f"Escaneando vulnerabilidades en {ip}...")
    try:
        nm.scan(ip, arguments='--script vuln')
        vulnerabilities = []
        if 'hostscript' in nm[ip]:
            for script in nm[ip]['hostscript']:
                script_name = script['id']
                output = script['output']
                severity = classify_severity(output)
                # Extraer CVE (si está presente) y buscar en ExploitDB
                cve_match = re.search(r'CVE-\d{4}-\d+', output)
                if cve_match:
                    cve_id = cve_match.group(0)
                    related_exploits = search_exploitdb(cve_id, exploit_dict)
                    vulnerabilities.append({'script': script_name, 'output': output, 'severidad': severity, 'cve': cve_id, 'exploitdb': related_exploits})
                else:
                    vulnerabilities.append({'script': script_name, 'output': output, 'severidad': severity})
        return vulnerabilities
    except Exception as e:
        print(f"Error al escanear {ip}: {e}")
        return []

# Clasificar la severidad de las vulnerabilidades
def classify_severity(output):
    if re.search(r'(critical|high)', output, re.IGNORECASE):
        return 'high'
    elif re.search(r'(medium|moderate)', output, re.IGNORECASE):
        return 'mid'
    elif re.search(r'(low|minor)', output, re.IGNORECASE):
        return 'low'
    else:
        return 'unknown'

# Mostrar el resumen final en la terminal
def display_summary(devices, total_vulnerabilities, severity_count):
    print("\n--- Resumen del Escaneo ---")
    print(f"Total de dispositivos conectados: {len(devices)}")
    print(f"Vulnerabilidades encontradas: {total_vulnerabilities}")
    print(f" Vulnerabilidades de severidad baja: {severity_count['low']}")
    print(f" Vulnerabilidades de severidad media: {severity_count['mid']}")
    print(f" Vulnerabilidades de severidad alta: {severity_count['high']}")
    print(f" Vulnerabilidades con severidad desconocida: {severity_count['unknown']}")

# Función principal del script
def main():
    parser = argparse.ArgumentParser(description="Escaneo de red para identificar dispositivos IoT y vulnerabilidades.")
    parser.add_argument('ip_range', type=str, help="Rango de IP a escanear (ej. 192.168.1.0/24)")
    parser.add_argument('--exploitdb_path', type=str, default='./exploitdb', help="Ruta a la base de datos de ExploitDB")
    args = parser.parse_args()

    ip_range = args.ip_range
    exploitdb_path = args.exploitdb_path

    devices = scan_network(ip_range)
    exploit_dict = load_exploitdb(exploitdb_path)
    total_vulnerabilities = 0
    severity_count = {'low': 0, 'mid': 0, 'high': 0, 'unknown': 0}
    vulnerabilities = []

    max_workers = multiprocessing.cpu_count() * 5 # Ajusta según la capacidad de tu sistema
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(detect_vulnerabilities, device['ip'], exploit_dict) for device in devices]
        for future in concurrent.futures.as_completed(futures):
            device_vulnerabilities = future.result()
            if device_vulnerabilities:
                for vuln in device_vulnerabilities:
                    print(f" - Script: {vuln['script']}, Severidad: {vuln['severidad'].capitalize()}")
                    if 'cve' in vuln:
                        print(f" - CVE: {vuln['cve']}")
                    if 'exploitdb' in vuln and vuln['exploitdb']:  # Verifica si 'exploitdb' está presente
                        print(f" - Exploits relacionados en ExploitDB: {len(vuln['exploitdb'])}")
                    severity_count[vuln['severidad']] += 1
                    total_vulnerabilities += 1
                    vulnerabilities.append(vuln)

    # Mostrar el resumen del escaneo
    display_summary(devices, total_vulnerabilities, severity_count)

# Ejecutar el script
if __name__ == "__main__":
    main()
