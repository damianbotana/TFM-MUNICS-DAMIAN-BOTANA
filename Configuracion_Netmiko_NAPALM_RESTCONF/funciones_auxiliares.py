import os
import json
import uuid
import ipaddress
import os
import yaml
import sys

ruta_fichero="claves.json"

def sumar_a_ip(ip,numero):
    '''
    ip: dirección ip
    numero: número a sumar a la dirección ip
    return: dirección ip con el número sumado
    '''
    ip = ipaddress.IPv4Address(ip)
    ip += numero
    return str(ip)


def cargar_claves(ruta_archivo):
    """
    Carga las claves y VPN IPs desde el archivo JSON.
    Si el archivo no existe, crea uno nuevo vacío.
    """
    if not os.path.exists(ruta_archivo):
        with open(ruta_archivo, 'w') as archivo:
            json.dump({}, archivo, indent=4)
        return {}
    with open(ruta_archivo, 'r') as archivo:
        try:
            return json.load(archivo)
        except json.JSONDecodeError:
            # Si el archivo está vacío o malformado, reiniciarlo
            return {}

def guardar_claves(ruta_archivo, claves_hosts):
    with open(ruta_archivo, 'w') as archivo:
        json.dump(claves_hosts, archivo, indent=4)

def obtener_ip_asignada(claves_hosts, base_vpn_ip):
    """
    Asigna una nueva IP VPN basada en la IP anterior más cuatro, para representar las conexiones punto a punto
    Si no hay IPs asignadas, comienza desde base_vpn_ip.

    :param claves_hosts: Diccionario con las claves y VPN IPs de los hosts.
    :param base_vpn_ip: Dirección IP base para comenzar la asignación.
    :return: Nueva dirección IP VPN como cadena.
    """
    usadas = sorted([
        ipaddress.IPv4Address(info['vpn_ip'])
        for info in claves_hosts.values()
        if 'vpn_ip' in info
    ])

    if usadas:
        # Toma la última IP asignada y agrega 1
        ultima_ip = usadas[-1]
        nueva_ip = ultima_ip + 1
    else:
        # Comienza desde base_vpn_ip + 1
        nueva_ip = ipaddress.IPv4Address(base_vpn_ip) + 1

    # Verifica que la nueva IP esté dentro de la subred VPN

    return str(nueva_ip)

def find_network_in_range(gateways, network):
    network_obj = ipaddress.ip_network(network, strict=False)
    
    for gateway in gateways:
        gateway_ip = ipaddress.ip_address(gateway)
        
        if gateway_ip in network_obj:
            return gateway_ip
    return None

def find_network_for_gateway(gateway, networks):
    gateway_ip = ipaddress.ip_address(gateway)
    for network, interface in networks:
        network_obj = ipaddress.ip_network(network, strict=False)
        if gateway_ip in network_obj:
            return (network, interface)
    return None

def convertir_cidr_a_diccionario(cidr_list):
    resultado = []
    for cidr in cidr_list:
        # Crear un objeto de red a partir del CIDR
        network = ipaddress.IPv4Network(cidr, strict=False)
        
        # Obtener la dirección de red y la máscara de red
        network_address = str(network.network_address)
        netmask = str(network.netmask)
        
        # Agregar al diccionario
        resultado.append({
            "direccion": network_address,
            "mascara": netmask
        })
    
    return resultado

def cidr_to_network_and_wildcard(cidr):
    # Crear un objeto de red a partir del CIDR
    network = ipaddress.IPv4Network(cidr, strict=False)
    
    # Obtener la dirección de red
    network_address = str(network.network_address)
    
    # Calcular la máscara wildcard
    netmask = network.netmask
    wildcard_mask = ipaddress.IPv4Address(int(netmask) ^ (2**32 - 1))
    
    return str(network_address)+" "+ str(wildcard_mask)

def cidr_to_network_and_wildcard_tuple(cidr):
    # Crear un objeto de red a partir del CIDR
    network = ipaddress.IPv4Network(cidr, strict=False)
    
    # Obtener la dirección de red
    network_address = str(network.network_address)
    
    # Calcular la máscara wildcard
    netmask = network.netmask
    wildcard_mask = ipaddress.IPv4Address(int(netmask) ^ (2**32 - 1))
    
    return str(network_address), str(wildcard_mask)
def obtener_parametros_vpn(host_vars):

    return {
            #"tipo_autenticacion": host_vars['tipo_autenticacion'],
            'encriptado':host_vars['encriptado'],
            'integridad':host_vars['integridad'],
            'grupo_dif':str(host_vars['grupo_dif']),
            "ip_vpn": host_vars['ip_vpn'],
            "ip_ca": host_vars['ip_ca'],

            "keyring_name": host_vars['keyring_name'],
            "proporsal_ike_name": host_vars['proporsal_ike_name'],
            "policy_name_ike_name": host_vars['policy_name_ike_name'],
            "profile_ike_v2_name": host_vars['profile_ike_v2_name'],
            "ipsec_name_profile":host_vars['ipsec_name_profile'],
            
    }

def sumar_a_ip(ip,numero):
    '''
    ip: dirección ip
    numero: número a sumar a la dirección ip
    return: dirección ip con el número sumado
    '''
    ip = ipaddress.IPv4Address(ip)
    ip += numero
    return str(ip)

def create_or_update_group_vars_file(group_name, variables, output_dir='group_vars'):
    # Crear el directorio group_vars si no existe
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Crear el archivo de variables del grupo
    group_vars_file = os.path.join(output_dir, f"{group_name}.yml")

    # Cargar el contenido existente del archivo YAML si existe
    if os.path.exists(group_vars_file):
        with open(group_vars_file, 'r') as f:
            existing_variables = yaml.safe_load(f) or {}
    else:
        existing_variables = {}

    # Actualizar o agregar las variables
    existing_variables.update(variables)

    # Escribir las variables en el archivo
    with open(group_vars_file, 'w') as f:
        yaml.dump(existing_variables, f, default_flow_style=False)

    print(f"Archivo de variables actualizado: {group_vars_file}")



def cargar_claves(ruta_archivo):
    """
    Carga las claves y VPN IPs desde el archivo JSON.
    Si el archivo no existe, crea uno nuevo vacío.
    """
    if not os.path.exists(ruta_archivo):
        with open(ruta_archivo, 'w') as archivo:
            json.dump({}, archivo, indent=4)
        return {}
    with open(ruta_archivo, 'r') as archivo:
        try:
            return json.load(archivo)
        except json.JSONDecodeError:
            # Si el archivo está vacío o malformado, reiniciarlo
            return {}

def guardar_claves(ruta_archivo, claves_hosts):
    with open(ruta_archivo, 'w') as archivo:
        json.dump(claves_hosts, archivo, indent=4)

def obtener_ip_asignada(claves_hosts, base_vpn_ip):
    """
    Asigna una nueva IP VPN basada en la IP anterior más cuatro, para representar las conexiones punto a punto
    Si no hay IPs asignadas, comienza desde base_vpn_ip.

    :param claves_hosts: Diccionario con las claves y VPN IPs de los hosts.
    :param base_vpn_ip: Dirección IP base para comenzar la asignación.
    :return: Nueva dirección IP VPN como cadena.
    """
    usadas = sorted([
        ipaddress.IPv4Address(info['vpn_ip'])
        for info in claves_hosts.values()
        if 'vpn_ip' in info
    ])

    if usadas:
        # Toma la última IP asignada y agrega 1
        ultima_ip = usadas[-1]
        nueva_ip = ultima_ip + 1
    else:
        # Comienza desde base_vpn_ip + 1
        nueva_ip = ipaddress.IPv4Address(base_vpn_ip) + 1

    # Verifica que la nueva IP esté dentro de la subred VPN

    return str(nueva_ip)

def obtener_ospf_id(claves_hosts):
    """
    A partir del numero 6500 se aumento el numero de ospf_id en 1 por cada equipo asignado
    """
    usadas = sorted([
        info['ospf_id']
        for info in claves_hosts.values()
        if 'ospf_id' in info
    ])

    if usadas:
        # Toma la última IP asignada y agrega 1
        ultima_id = usadas[-1]
        nueva_id = ultima_id + 1
    else:
        # Comienza desde base_vpn_ip + 1
        nueva_id = 6500

    # Verifica que la nueva IP esté dentro de la subred VPN

    return nueva_id

def generar_crear_osfp_id( nombre_equipo):
    claves_hosts = cargar_claves(ruta_fichero)

    if not claves_hosts or nombre_equipo not in claves_hosts:
        ospf_id = obtener_ospf_id(claves_hosts)
    else:
        if 'ospf_id' in claves_hosts[nombre_equipo]:
            ospf_id = claves_hosts[nombre_equipo]['ospf_id']
            print(f"El equipo {nombre_equipo} ya tiene el campo 'ospf_id': {ospf_id}")
        else:
            ospf_id = obtener_ospf_id(claves_hosts)
            claves_hosts[nombre_equipo]['ospf_id'] = ospf_id
            guardar_claves(ruta_fichero, claves_hosts)
            print(f"Se ha asignado un nuevo 'ospf_id' al equipo {nombre_equipo}: {ospf_id}")

    return ospf_id
def obtener_clave_y_ip(ruta_archivo, nombre_equipo, base_vpn_ip):
    """
    Obtiene la clave y la VPN IP para un equipo. Si el equipo no existe,
    crea una nueva entrada con una clave UUID y asigna una VPN IP.

    :param ruta_archivo: Ruta al archivo JSON.
    :param nombre_equipo: Nombre del equipo.
    :param base_vpn_ip: Dirección IP base para asignar la primera VPN IP.
    :return: Tuple (clave, vpn_ip)
    """
    claves_hosts = cargar_claves(ruta_archivo)


    if claves_hosts=={} or nombre_equipo not in claves_hosts:
        # Generar una nueva clave UUID
        clave = str(uuid.uuid4())
        # Asignar una nueva VPN IP
        vpn_ip = obtener_ip_asignada(claves_hosts, base_vpn_ip)
        ospf_id= obtener_ospf_id(claves_hosts)
        # Crear una nueva entrada para el equipo
        claves_hosts[nombre_equipo] = {
            "key": clave,
            "vpn_ip": vpn_ip,
            "ospf_id":ospf_id

        }

        # Guardar las actualizaciones en el archivo
        guardar_claves(ruta_archivo, claves_hosts)
    else:
        # Obtener la clave y VPN IP existentes
        clave = claves_hosts[nombre_equipo].get("key")
        vpn_ip = claves_hosts[nombre_equipo].get("vpn_ip")


        # Si la VPN IP no está asignada, asignarla ahora
        if not vpn_ip:
            vpn_ip = obtener_ip_asignada(claves_hosts, base_vpn_ip)
            claves_hosts[nombre_equipo]["vpn_ip"] = vpn_ip
            guardar_claves(ruta_archivo, claves_hosts)

    return clave, vpn_ip

