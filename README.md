# TFM-Automatización de las tareas de fortificación de una infraestructura de red

## Introducción
El siguiente proyecto corresponde con el TFM del máster de ciberseguridad, en la que se van automatizar las tareas de habilitar el acceso remoto mediante SSH, despliegue de una VPN entre los diferentes equipos de una organización y la aplicación de las políticas de seguridad definidas en un fichero Excel. Para la automatización se utilizarán Netmiko, NAPALM, Ansible y RESTCONF y los dispositivos que se aplicarán las configuraciones son dispositivos de IOS de Cisco.
## Estructura del proyecto

El siguiente proyecto se encuentra organizado en dos carpetas principales:  

- **Ansible**  
- **Configuracion_Netmiko_NAPALM_RESTCONF**  

Esta división responde a la forma en que se implementaron las tareas con las herramientas seleccionadas. Además, el propósito de la organización de las carpetas es agrupar en una misma carpeta las partes comunes de cada implementación. Por ejemplo, en el caso de Netmiko, NAPALM y RESTCONF, se comparten las operaciones de lectura del inventario, mientras que las operaciones específicas de cada herramienta se encuentran en subcarpetas a un nivel inferio.
Debido a que Ansible emplea un lenguaje y un proceso de configuración diferentes, no fue posible integrarlo con las otras herramientas



### 📂 Carpeta `Ansible`  

Dentro de esta carpeta, se encuentran tres subcarpetas, cada una conteniendo los **playbooks** necesarios para la implementación de las tareas planteadas.

### 📂 Carpeta `Configuracion_Netmiko_NAPALM_RESTCONF`  

Esta carpeta se divide en dos subcarpetas:  

- **`RESTCONF`**  
- **`Netmiko_NAPALM`**  

Cada una de ellas contiene la implementación de las herramientas correspondientes para las tareas de automatización, así como el código necesario para acceder a los dispositivos.  

Se decidió agrupar **Netmiko y NAPALM** en una misma carpeta, ya que ambas herramientas utilizan comandos de configuración de **Cisco**, permitiendo compartir una gran parte de su implementación.  

#### 📜 Archivos Principales  

Dentro de la carpeta `Configuracion_Netmiko_NAPALM_RESTCONF`, se encuentran los siguientes archivos clave:  

- **`leer_inventario.py`**  
  - Obtiene la información almacenada en el inventario de **Ansible** y la distribuye a cada herramienta.  

- **`formato_credenciales_acceso_herramienta.py`**  
  - Transforma los parámetros del inventario al formato adecuado para cada herramienta de automatización.  
  - Contiene funciones específicas para la ejecución de tareas con cada herramienta.  

- **`automatizacion_redes.py`**  
  - Permite al usuario seleccionar qué tarea ejecutar y con qué herramienta hacerlo.  

### 📂 Estructura del Proyecto  

A continuación, se muestra de forma visual la estructura del proyecto:


- 📂 Ansible  
  - 📂 Aplicación políticas de seguridad  
    - 📄 Aplicacion_politicas_con_ACL.yml  
    - 📄 Aplicacion_politicas_con_ZFW.yml  
  - 📂 Despliegue VPN  
    - 📄 Configuracion_CA.yml  
    - 📄 Configuracion_NAT_recepcion_VPN.yml  
    - 📄 Despliegue_VPN.yml  
  - 📂 Habilitar SSH en los equipos  
     - 📄 Habilitar_SSH.yaml  
  - 📦 inventario.ini  
  - 📜 politica_seguridad.xlsx  

- 📂 Configuracion_Netmiko_NAPALM_RESTCONF  
  - ⚙️ automatizacion_redes.py  
  - 📄 formato_credenciales_acceso_herramienta.py  
  - 📄 funciones_auxiliares.py  
  - 📦 inventario.ini  
  - 📄 leer_inventario.py  
  - 📂 Netmiko_NAPALM  
    - 📄 Aplicacion_politicas_seguridad_Netmiko_NAPALM.py  
    - 📂 Comandos_Cisco_parametrizados  
      - 📄 Comandos_parametrizados_Cisco_Aplicacion_control_trafico.py  
      - 📄 Comandos_paremetrizados_configuracion_VPN.py  
    - 📄 Configuracion_SSH_con_Netmiko_NAPALM.py  
    - 📄 Despliegue_VPN_Netmiko_NAPALM.py  
    - 📂 NAPALM  
      - 📄 configuracion_acceso_dispositivo_NAPALM.py  
      - 📄 Obtener_informacion_NAPALM.py  
    - 📂 Netmiko  
      - 📄 configuracion_acceso_dispositivos_netmiko.py  
      - 📄 Obtener_informacion_Netmiko.py  
  - 📜 politica_seguridad.xlsx  
  - 📂 RESTCONF  
    - 📄 Aplicar_politicas_seguridad.py  
    - 📄 Configuraccion_acceso_dispositivos_RESTCONF.py  
    - 📄 Despliegue_VPN.py  
    - 📄 Habilitar_SSH_dispositivos.py  

- 📄 LICENSE  
- 📄 README.md  

## Despliegue del Proyecto

Para la utilización de las herramientas, se distinguirá entre **Ansible** y el resto de herramientas, ya que su modo de ejecución es diferente en cada caso.

### Ansible

Para ejecutar una tarea en **Ansible**, primero es necesario seleccionar el *playbook* que se desea ejecutar en función de la tarea a realizar.  

Una vez seleccionado el *playbook*, se debe especificar los grupos asignados en el inventario sobre los que se aplicará la tarea. Por defecto, estos grupos están configurados según el inventario predeterminado.  

Además, es importante mencionar que **se deben utilizar los Vaults de Ansible** para proporcionar las credenciales de acceso a los dispositivos, ya que el sistema está configurado para este propósito.  

A continuación, se muestra un ejemplo de cómo ejecutar una tarea con Ansible:

```bash
ansible-playbook playbook.yml -i inventario.ini --vault-password-file .vault_pass.txt 
```

### Resto de técnologias
Para el resto de tecnologías, se empleará el script de Python automatizacion_redes.py, que permite la ejecución de las tareas correspondientes.

Para su uso, se debe proporcionar la herramienta a ejecutar y la tarea a realizar. En algunos casos, dependiendo de la tarea, se pueden solicitar parámetros adicionales.

Los parámetros pueden pasarse de dos formas:

 1) Mediante argumentos directos al ejecutar el comando.
2) Dejando que el programa los solicite interactivamente si se ejecuta sin parámetros.

A continuación, se muestra un ejemplo de cómo obtener las operaciones y herramientas disponibles en esta herramienta:

```bash
python3 automatizacion_redes.py -h
```


