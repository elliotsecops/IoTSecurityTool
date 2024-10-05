# IoTSecurityTool (ESP)

## Descripción del Proyecto

Este script es una herramienta de escaneo de red diseñada para identificar dispositivos IoT y detectar vulnerabilidades en ellos. Esta herramienta utiliza Nmap para escanear la red y detectar dispositivos, y luego ejecuta scripts NSE (Nmap Scripting Engine) para identificar vulnerabilidades conocidas. Además, utiliza la base de datos de ExploitDB para buscar exploits relacionados con las vulnerabilidades detectadas.

### Objetivos del Proyecto

1. **Identificar Dispositivos IoT**: Escanear la red para detectar dispositivos IoT conectados.
2. **Detectar Vulnerabilidades**: Utilizar scripts NSE de Nmap para detectar vulnerabilidades en los dispositivos.
3. **Buscar Exploits Relacionados**: Utilizar la base de datos de ExploitDB para buscar exploits relacionados con las vulnerabilidades detectadas.
4. **Generar Informes Detallados**: Generar un informe en formato JSON con los detalles de los dispositivos y sus vulnerabilidades.

## Requisitos del Sistema

- **Python 3.x**: El script está escrito en Python 3.
- **Nmap**: Necesario para realizar el escaneo de red y ejecutar scripts NSE.
- **ExploitDB**: Necesario para buscar exploits relacionados con las vulnerabilidades detectadas.

### Dependencias de Python

- **python-nmap**: Librería de Python para interactuar con Nmap.
- **argparse**: Librería de Python para manejar argumentos de línea de comandos.


## Configuración del Proyecto

### 1. Clonar el Repositorio

Clona el repositorio del proyecto en tu máquina local:

```bash
git clone https://github.com/elliotsecops/IoTSecurityTool.git
cd IoTSecurityTool
```

### 2. Configurar el Entorno Virtual

Crea y activa un entorno virtual para el proyecto:

```bash
python3 -m venv myenv
source myenv/bin/activate
```

### 3. Instalar Dependencias

Instala las dependencias de Python dentro del entorno virtual:
(la versión de nmap que debas descargar puede depender de tu maquina así que si la descarga falla entonces intenta con sus variantes)

```bash
pip install python-nmap argparse
```

### 4. Descargar ExploitDB

Descarga la base de datos de ExploitDB y colócala en la ruta correcta:
(Debes saber muy bien el path donde guardas la descarga porque será necesario para el escaneo, por ejemplo `/home/you-user/exploitdb` ):

```bash
git clone https://gitlab.com/exploit-database/exploitdb.git 
```

## Ejecución del Script

### 1. Ejecutar el Script con `sudo`

El script requiere privilegios de root para realizar el escaneo de detección de sistema operativo. Ejecuta el script con `sudo`:

```bash
sudo -E $(which python3) main.py 192.168.1.0/24 --exploitdb_path /home/elliot/exploitdb
```

### 2. Ejemplo de Ejecución

Aquí tienes un ejemplo completo de cómo ejecutar el script:

```bash
# Navegar al directorio del proyecto
cd `/home/you-user/Downloads/IoTSecurityTool`

# Activar el entorno virtual
source myenv/bin/activate

# Ejecutar el script con sudo -E y la ruta correcta donde clonaste el repositorio de ExploitDB
sudo -E $(which python3) main.py 192.168.1.0/24 --exploitdb_path /home/your-user/exploitdb
```

## Interpretación de los Resultados

### Ejemplo de Salida Esperada

```bash
Escaneando la red: 192.168.1.0/24...
Dispositivo encontrado: IP 192.168.1.1, MAC C0:25:2F:97:A5:69, Fabricante Shenzhen Mercury Communication Technologies
Dispositivo encontrado: IP 192.168.1.100, MAC 10:3F:44:70:9D:C2, Fabricante Xiaomi Communications
Dispositivo encontrado: IP 192.168.1.102, MAC F8:A9:D0:97:B0:13, Fabricante LG Electronics (Mobile Communications)
Dispositivo encontrado: IP 192.168.1.104, MAC 66:43:88:60:1C:60, Fabricante Unknown
Dispositivo encontrado: IP 192.168.1.110, MAC 34:CF:F6:B3:D8:B4, Fabricante Intel Corporate
Escaneando vulnerabilidades en 192.168.1.1...
Escaneando vulnerabilidades en 192.168.1.100...
Escaneando vulnerabilidades en 192.168.1.102...
Escaneando vulnerabilidades en 192.168.1.104...
Escaneando vulnerabilidades en 192.168.1.110...
 - Script: smb-vuln-ms10-061, Severidad: Unknown
 - Script: samba-vuln-cve-2012-1182, Severidad: Unknown
 - Script: smb-vuln-ms10-054, Severidad: Unknown

--- Resumen del Escaneo ---
Total de dispositivos conectados: 5
Vulnerabilidades encontradas: 3
 Vulnerabilidades de severidad baja: 0
 Vulnerabilidades de severidad media: 0
 Vulnerabilidades de severidad alta: 0
 Vulnerabilidades con severidad desconocida: 3
```

### Resumen de los Resultados

1. **Dispositivos Detectados**:
   - **IP 192.168.1.1**: MAC C0:25:2F:97:A5:69, Fabricante Shenzhen Mercury Communication Technologies
   - **IP 192.168.1.100**: MAC 10:3F:44:70:9D:C2, Fabricante Xiaomi Communications
   - **IP 192.168.1.102**: MAC F8:A9:D0:97:B0:13, Fabricante LG Electronics (Mobile Communications)
   - **IP 192.168.1.104**: MAC 66:43:88:60:1C:60, Fabricante Unknown
   - **IP 192.168.1.110**: MAC 34:CF:F6:B3:D8:B4, Fabricante Intel Corporate

2. **Vulnerabilidades Detectadas**:
   - **Script: smb-vuln-ms10-061**, Severidad: Unknown
   - **Script: samba-vuln-cve-2012-1182**, Severidad: Unknown
   - **Script: smb-vuln-ms10-054**, Severidad: Unknown

3. **Resumen del Escaneo**:
   - Total de dispositivos conectados: 5
   - Vulnerabilidades encontradas: 3
   - Vulnerabilidades de severidad baja: 0
   - Vulnerabilidades de severidad media: 0
   - Vulnerabilidades de severidad alta: 0
   - Vulnerabilidades con severidad desconocida: 3

### Análisis de las Vulnerabilidades

Las vulnerabilidades detectadas son:

1. **smb-vuln-ms10-061**:
   - **Descripción**: Vulnerabilidad en el servicio SMB de Microsoft que afecta a sistemas Windows.
   - **Severidad**: Unknown (desconocida).

2. **samba-vuln-cve-2012-1182**:
   - **Descripción**: Vulnerabilidad en Samba que permite la ejecución remota de código.
   - **Severidad**: Unknown (desconocida).

3. **smb-vuln-ms10-054**:
   - **Descripción**: Vulnerabilidad en el servicio SMB de Microsoft que afecta a sistemas Windows.
   - **Severidad**: Unknown (desconocida).

### Próximos Pasos

1. **Investigar las Vulnerabilidades**:
   - Investiga más sobre las vulnerabilidades detectadas para entender su impacto y cómo mitigarlas. Puedes buscar información en sitios como [CVE Details](https://www.cvedetails.com/) o [NVD (National Vulnerability Database)](https://nvd.nist.gov/).

2. **Aplicar Parches y Actualizaciones**:
   - Asegúrate de que todos los dispositivos en tu red estén actualizados con los últimos parches de seguridad.

3. **Configurar Firewalls y ACLs**:
   - Configura firewalls y listas de control de acceso (ACLs) para restringir el acceso a servicios vulnerables.

4. **Monitorización Continua**:
   - Implementa una solución de monitorización continua para detectar y responder a nuevas vulnerabilidades.

## Contribuciones

¡Las contribuciones son bienvenidas! Si deseas contribuir al proyecto, sigue estos pasos:

1. **Fork** el repositorio.
2. Crea una nueva rama (`git checkout -b feature/nueva-funcionalidad`).
3. Realiza tus cambios y haz commit (`git commit -m 'Añadir nueva funcionalidad'`).
4. Sube tus cambios a la rama (`git push origin feature/nueva-funcionalidad`).
5. Abre un **Pull Request**.

## Licencia

Este proyecto está bajo la licencia [MIT](LICENSE).

---

# IoT Security Tool (ENG)

## Project Description

This script is a network scanning tool designed to identify IoT devices and detect vulnerabilities in them. This tool uses Nmap to scan the network and detect devices, and then runs NSE (Nmap Scripting Engine) scripts to identify known vulnerabilities. Additionally, it uses the ExploitDB database to search for exploits related to the detected vulnerabilities.

### Project Objectives

1. **Identify IoT Devices**: Scan the network to detect connected IoT devices.
2. **Detect Vulnerabilities**: Use NSE scripts from Nmap to detect vulnerabilities in devices.
3. **Search for Related Exploits**: Use the ExploitDB database to search for exploits related to the detected vulnerabilities.
4. **Generate Detailed Reports**: Generate a report in JSON format with details of devices and their vulnerabilities.

## System Requirements

- **Python 3.x**: The script is written in Python 3.
- **Nmap**: Required to perform network scanning and run NSE scripts.
- **ExploitDB**: Required to search for exploits related to detected vulnerabilities.

### Python Dependencies

- **python-nmap**: Python library to interact with Nmap.
- **argparse**: Python library to handle command-line arguments.

## Project Configuration

### 1. Clone the Repository

Clone the project repository to your local machine:

```bash
git clone https://github.com/elliotsecops/IoTSecurityTool.git
cd IoTSecurityTool
```

### 2. Configure the Virtual Environment

Create and activate a virtual environment for the project:

```bash
python3 -m venv myenv
source myenv/bin/activate
```

### 3. Install Dependencies

Install Python dependencies within the virtual environment:

```bash
pip install python-nmap argparse
```

### 4. Download ExploitDB

Download the ExploitDB database and place it in the correct path:

```bash
git clone https://gitlab.com/exploit-database/exploitdb.git
```

## Running the Script

### 1. Run the Script with `sudo`

The script requires root privileges to perform the operating system detection scan. Run the script with `sudo`:

```bash
sudo -E $(which python3) main.py 192.168.1.0/24 --exploitdb_path /home/elliot/exploitdb
```

### 2. Example Run

Here is a complete example of how to run the script:

```bash
# Navigate to the project directory
cd `/home/you-user/Downloads/IoTSecurityTool`

# Activate the virtual environment
source myenv/bin/activate

# Run the script with sudo -E and the correct path where you cloned the ExploitDB repository
sudo -E $(which python3) main.py 192.168.1.0/24 --exploitdb_path /home/your-user/exploitdb
```

## Interpreting the Results

### Expected Output Example

```bash
Scanning the network: 192.168.1.0/24...
Device found: IP 192.168.1.1, MAC C0:25:2F:97:A5:69, Manufacturer Shenzhen Mercury Communication Technologies
Device found: IP 192.168.1.100, MAC 10:3F:44:70:9D:C2, Manufacturer Xiaomi Communications
Device found: IP 192.168.1.102, MAC F8:A9:D0:97:B0:13, Manufacturer LG Electronics (Mobile Communications)
Device found: IP 192.168.1.104, MAC 66:43:88:60:1C:60, Manufacturer Unknown
Device found: IP 192.168.1.110, MAC 34:CF:F6:B3:D8:B4, Manufacturer Intel Corporate
Scanning vulnerabilities in 192.168.1.1...
Scanning vulnerabilities in 192.168.1.100...
Scanning vulnerabilities in 192.168.1.102...
Scanning vulnerabilities in 192.168.1.104...
Scanning vulnerabilities in 192.168.1.110...
 - Script: smb-vuln-ms10-061, Severity: Unknown
 - Script: samba-vuln-cve-2012-1182, Severity: Unknown
 - Script: smb-vuln-ms10-054, Severity: Unknown

--- Scan Summary ---
Total connected devices: 5
Vulnerabilities found: 3
 Low severity vulnerabilities: 0
 Medium severity vulnerabilities: 0
 High severity vulnerabilities: 0
 Unknown severity vulnerabilities: 3
```

### Summary of Results

1. **Detected Devices**:
   - **IP 192.168.1.1**: MAC C0:25:2F:97:A5:69, Manufacturer Shenzhen Mercury Communication Technologies
   - **IP 192.168.1.100**: MAC 10:3F:44:70:9D:C2, Manufacturer Xiaomi Communications
   - **IP 192.168.1.102**: MAC F8:A9:D0:97:B0:13, Manufacturer LG Electronics (Mobile Communications)
   - **IP 192.168.1.104**: MAC 66:43:88:60:1C:60, Manufacturer Unknown
   - **IP 192.168.1.110**: MAC 34:CF:F6:B3:D8:B4, Manufacturer Intel Corporate

2. **Detected Vulnerabilities**:
   - **Script: smb-vuln-ms10-061**, Severity: Unknown
   - **Script: samba-vuln-cve-2012-1182**, Severity: Unknown
   - **Script: smb-vuln-ms10-054**, Severity: Unknown

3. **Scan Summary**:
   - Total connected devices: 5
   - Vulnerabilities found: 3
   - Low severity vulnerabilities: 0
   - Medium severity vulnerabilities: 0
   - High severity vulnerabilities: 0
   - Unknown severity vulnerabilities: 3

### Vulnerability Analysis

The detected vulnerabilities are:

1. **smb-vuln-ms10-061**:
   - **Description**: Vulnerability in Microsoft's SMB service affecting Windows systems.
   - **Severity**: Unknownosoft SMB service affecting Windows systems.
   - **Severity**: Unknown.

2. **samba-vuln-cve-2012-1182**:
   - **Description**: Vulnerability in Samba allowing remote code execution.
   - **Severity**: Unknown.

3. **smb-vuln-ms10-054**:
   - **Description**: Vulnerability in the Microsoft SMB service affecting Windows systems.
   - **Severity**: Unknown.

### Next Steps

1. **Investigate Vulnerabilities**:
   - Research the detected vulnerabilities to understand their impact and how to mitigate them. You can search for information on sites like [CVE Details](https://www.cvedetails.com/) or [NVD (National Vulnerability Database)](https://nvd.nist.gov/).

2. **Apply Patches and Updates**:
   - Ensure that all devices on your network are updated with the latest security patches.

3. **Configure Firewalls and ACLs**:
   - Configure firewalls and access control lists (ACLs) to restrict access to vulnerable services.

4. **Continuous Monitoring**:
   - Implement a continuous monitoring solution to detect and respond to new vulnerabilities.

## Contributions

Contributions are welcome! If you want to contribute to the project, follow these steps:

1. **Fork** the repository.
2. Create a new branch (`git checkout -b feature/new-feature`).
3. Make your changes and commit (`git commit -m 'Add new feature'`).
4. Push your changes to the branch (`git push origin feature/new-feature`).
5. Open a **Pull Request**.

## License

This project is under the [MIT](LICENSE) license.