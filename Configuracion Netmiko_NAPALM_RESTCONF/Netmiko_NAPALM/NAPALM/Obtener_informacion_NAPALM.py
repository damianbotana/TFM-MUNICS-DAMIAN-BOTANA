from ..funciones_auxiliares import obtener_clave_y_ip,create_or_update_group_vars_file
from ipaddress import IPv4Address,
import re
import ipaddress
from configuracion_acceso_dispositivo_NAPALM import obtener_informacion_napalm


def obtener_datos_cpe_nat_vpn_napalm(host,parametros,host_vars,grupo_aplicado):
    """
        Obtiene y procesa información del dispositivo CPE utilizando NAPALM.
        Args:
            host (str): Dirección del host del dispositivo.
            parametros (dict): Diccionario de parámetros que incluye configuraciones y opciones.
            host_vars (dict): Variables del host que incluyen información de grupos y dispositivos.
            grupo_aplicado (str): Nombre del grupo aplicado.
        Returns:
            dict: Diccionario con los parámetros actualizados.
        Este método realiza las siguientes acciones:
        1. Obtiene información del dispositivo utilizando NAPALM.
        2. Extrae la IP del vecino OSPF del resultado del comando 'show ip ospf neighbor'.
        3. Si el formato de red no es el mismo para todos los dispositivos, solicita al usuario que elija una IP de las redes conectadas.
        4. Pregunta al usuario si la red tiene el mismo formato para el resto de dispositivos y actualiza los parámetros en consecuencia.
        5. Actualiza los parámetros con la red interna, interfaz de red, origen, IP del firewall y IP del CPE.
        6. Guarda la información en las variables del grupo correspondiente.
    """


    diccionario=obtener_informacion_napalm(host,["ip_interfaz_internet",["show ip ospf neighbor","show ip route connected"]],["ip_puerta_enlace","ospf"])

    neighbor_ip_match = re.search(r'^\s*\S+\s+\d+\s+\S+\s+\S+\s+([0-9.]+)\s+\S+', diccionario['show ip ospf neighbor'], re.MULTILINE)

    neighbor_ip = neighbor_ip_match.group(1) if neighbor_ip_match else None


    if not parametros['mismo_formato_red']:
        redes_conectadas = re.findall(r'C\s+([0-9.]+/[0-9]+)', diccionario['show ip route connected'])

        # 3. Solicitar entrada del usuario
        ip_elegida = input(f"Escribe la opción que deseas usar (elige una de las siguientes IPs: {redes_conectadas}): ")
        #pregunta al usuario si la red tiene  el mismo formato para el resto de dispositivos y se valida la respuesta en caso de que no sea s/n se vuelve a pregunta

        mismo_formato_red=input("¿La red tiene el mismo formato para el resto de dispositivos? (s/n): ")
        while mismo_formato_red not in ["s","n"]:
            mismo_formato_red=input("¿La red tiene el mismo formato para el resto de dispositivos? (s/n): ")

        #indicativo para que el usuario no tenga que volver a preguntarle por la red
        if mismo_formato_red=="s":
            parametros['mismo_formato_red']=True
            parametros['ip_elegida']=ip_elegida
    else:
        ip_elegida=parametros['ip_elegida']


    parametros['red_interna']=[ {
        "ip":_cidr_to_network_and_wildcard(ip_elegida),
        "destino": "any",
    }
    ]

    parametros['interfaz_red']= diccionario['interfaz_internet']
    parametros['origen']="inside"
    parametros['ip_fw']=[neighbor_ip]
    parametros['ip_cpe']=sumar_a_ip(diccionario['ip_puerta_enlace'],14)
    #guardar dicha informacion en las variables del grupo
    grupo_zona = next((grupo for grupo in host_vars['group_names'] if grupo.startswith('zona')), None)


    create_or_update_group_vars_file(grupo_zona,{"red_interna_paso_vpn" : ip_elegida})
    for firewall in host_vars['groups']['firewalls']:
        for integrante_zona in host_vars['groups'][grupo_zona]:

            if firewall == integrante_zona:

                create_or_update_group_vars_file("firewalls",{"ip_recepcion_vpn"+str(firewall): parametros['ip_cpe']})


                return parametros

def obtener_datos_firewall_nat_napalm(host,parametros,host_vars,grupo_aplicado):

    parametros.update(_obtener_parametros_vpn(host_vars))
    comandos = [['show ip route ospf', 'show ip int brief']]
    informacion_obtenida = ['redes_ospf', 'ips_propias']
    resultados = obtener_informacion_napalm(host, comandos, informacion_obtenida)

    # Extraer redes OSPF utilizando expresiones regulares
    ospf_networks = re.findall(r'O\s+([0-9.]+/[0-9]+)', resultados['show ip route ospf'])
    print(f"Redes OSPF: {ospf_networks}")


    # Extraer direcciones IP conectadas al equipo
    redes_conectadas = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', resultados['show ip int brief'])
    print(f"Redes conectadas: {redes_conectadas}")

    # Determinar la IP conectada al ISP
    ip_firewall_a_cpe = _find_network_in_range( redes_conectadas,host_vars['red_interna_paso_vpn'])

    print(f"IP conectada al ISP: {ip_firewall_a_cpe}")

    parametros['ip_interna']=ip_firewall_a_cpe
    print(host_vars['ip_recepcion_vpn'])
    print(host_vars)
    if host_vars['inventory_hostname'] not in parametros:
        parametros[host_vars['inventory_hostname']] = {}

    for i,firewall in enumerate(host_vars['groups']['firewalls']):

            if 'ip_recepcion_vpn' + str(firewall) in host_vars:
                if firewall not in parametros:
                    parametros[firewall] = {}
                parametros[firewall]['ip_cpe'] = host_vars['ip_recepcion_vpn' + str(firewall)]
            else:
                print(f"Clave 'ip_recepcion_vpn{firewall}' no encontrada en host_vars")
            parametros[firewall]['bgp_id'] = 65000 + i


    parametros['redes_compartir']=_convertir_cidr_a_diccionario(ospf_networks)


    #se obtiene el dispositivo que funcionara como hub de la vpn
    parametros['hub_vpn']=host_vars['groups'][grupo_aplicado][0]

    return parametros

def obtener_acl_firewall_napalm_informacion(host, parametros, host_vars, grupo_aplicado):
    """
    Obtiene información del dispositivo de red utilizando Netmiko y actualiza los parámetros proporcionados.

    Parámetros:
    host (str): Dirección IP o nombre del host del dispositivo de red.
    parametros (dict): Diccionario de parámetros que se actualizarán con la información obtenida.
    host_vars (dict): Diccionario que contiene variables específicas del host, como redes y VLANs.
    grupo_aplicado (str): Grupo al que pertenece el dispositivo.

    Retorna:
    dict: Diccionario de parámetros actualizado con la información obtenida del dispositivo de red.

    La función realiza las siguientes acciones:
    1. Obtiene información del dispositivo utilizando comandos Netmiko.
    2. Extrae el gateway predeterminado de la tabla de enrutamiento.
    3. Extrae información de vecinos OSPF.
    4. Extrae la IP propia del dispositivo en OSPF.
    5. Obtiene la interfaz de administración del dispositivo.
    6. Genera comandos y variables para las VLANs.
    7. Obtiene servidores DHCP configurados en el dispositivo.
    8. Actualiza el diccionario de parámetros con la información obtenida.
    """
    diccionario = obtener_informacion_napalm(
        host,
        ["show ip route", "show ip ospf neighbor", "show ip route " + host_vars['red_administracion'], "show ip route ospf", "show run | include ip helper-address"],
        ["routing_table", "ospf_neighbor", "red_administracion", "redes_ospf", "ips_dhcp"]
    )

    # Extraer gateway de la ruta predeterminada
    default_gateway_match = re.search(r"0\.0\.0\.0/0.*via.*?,.*?,\s*(\S+)$", diccionario["routing_table"], re.MULTILINE)
    default_gateway = default_gateway_match.group(1) if default_gateway_match else None
    print(default_gateway)

    # Extraer vecino OSPF
    ospf_neighbor_output = re.findall(r"\S+\s+\d+\s+\S+\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+" + default_gateway, diccionario["ospf_neighbor"])
    print("La informacion del dispositivo es ")

    # Extraer IP propia de OSPF
    ip_propia_opspf_match = re.search(r"L\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+is directly connected, " + default_gateway, diccionario["routing_table"], re.MULTILINE)
    ip_propia_opspf = ip_propia_opspf_match.group(1) if ip_propia_opspf_match else None
    print(ip_propia_opspf.split("/")[0])

    # Obtener interfaz de administración
    interfaces = re.findall(r'\s+(GigabitEthernet\d+|FastEthernet\d+|Serial\d+|Tunnel\d+|Loopback\d+|Vlan\d+)$', diccionario["red_administracion"], re.MULTILINE)
    print(f"Interfaz de administración: {interfaces[0]}")

    # Obtener comandos y variables para las VLANs
    lista_comandos = [f"show ip route {direccion}" if direccion != 'any' else "show ip route 0.0.0.0" for vlan, direccion in host_vars['vlan_ips'].items()]
    lista_variables = list(host_vars['vlan_ips'].keys())

    # Obtener servidores DHCP
    dhcp_servers = list(set(re.findall(r"ip helper-address (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", diccionario["ips_dhcp"])))

    diccionario = obtener_informacion_napalm(host, lista_comandos, lista_variables)
    pattern = r'\s+(GigabitEthernet\d+|FastEthernet\d+|Serial\d+|Tunnel\d+|Loopback\d+|Vlan\d+)$'
    pattern2 = r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    interfaz_redes = {"Tunnel0": []}

    for red in lista_variables:
        if diccionario[red]:
            interfaces = re.findall(pattern, diccionario[red], re.MULTILINE)
            ips = re.findall(pattern2, diccionario[red], re.MULTILINE)

            if ips and ipaddress.ip_address(ips[0]) in ipaddress.ip_network(host_vars['red_vpn']):
                interfaz_redes["Tunnel0"].append(red)
                continue

            if interfaces:
                interfaz_redes.setdefault(interfaces[0], []).append(red)

    print(interfaz_redes)

    # Actualizar parámetros
    parametros.update({
        'vecino_ospf': ospf_neighbor_output[0],
        'ip_propia_ospf': ip_propia_opspf.split("/")[0],
        'interfaz_administracion': interfaces[0],
        'interfaz_internet': default_gateway,
        'interfaces_redes': interfaz_redes,
        'vlan_ips': host_vars['vlan_ips'],
        'dhcp_servers': dhcp_servers
    })

    return parametros


