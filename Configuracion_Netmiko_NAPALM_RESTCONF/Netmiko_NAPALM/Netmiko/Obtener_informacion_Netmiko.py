from funciones_auxiliares import cidr_to_network_and_wildcard,find_network_for_gateway,sumar_a_ip, convertir_cidr_a_diccionario,find_network_in_range,obtener_clave_y_ip,create_or_update_group_vars_file,obtener_parametros_vpn
from ipaddress import IPv4Address
from Netmiko_NAPALM.Netmiko.configuracion_acceso_dispositivos_netmiko import lectura_datos_netmiko
import re
import ipaddress

def obtener_acl_firewall_netmiko_informacion(host, parametros, host_vars, grupo_aplicado):
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
    diccionario = lectura_datos_netmiko(
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

    diccionario = lectura_datos_netmiko(host, lista_comandos, lista_variables)
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

def obtener_vpn_firewall_netmiko_informacion(host,parametros,host_vars,grupo_aplicado):
    """
        Obtiene información de la VPN y firewall utilizando Netmiko y actualiza los parámetros proporcionados.
        Args:
            host (str): Dirección del host del dispositivo.
            parametros (dict): Diccionario de parámetros que se actualizarán con la información obtenida.
            host_vars (dict): Variables del host que contienen información de configuración.
            grupo_aplicado (str): Nombre del grupo aplicado para determinar el hub de la VPN.
        Returns:
            dict: Diccionario de parámetros actualizado con la información obtenida.
        Funcionalidad:
            - Actualiza los parámetros con información de VPN obtenida de host_vars.
            - Ejecuta comandos en el dispositivo para obtener rutas OSPF y direcciones IP.
            - Extrae redes OSPF y direcciones IP conectadas utilizando expresiones regulares.
            - Determina la IP conectada al ISP y la actualiza en los parámetros.
            - Actualiza los parámetros con información de BGP y redes a compartir.
            - Determina el dispositivo que funcionará como hub de la VPN.
    """

    parametros.update(obtener_parametros_vpn(host_vars))
    comandos = ['show ip route ospf', 'show ip int brief']
    informacion_obtenida = ['redes_ospf', 'ips_propias']
    resultados = lectura_datos_netmiko(host, comandos, informacion_obtenida)

    # Extraer redes OSPF utilizando expresiones regulares
    ospf_networks = re.findall(r'O\s+([0-9.]+/[0-9]+)', resultados['redes_ospf'])
    print(f"Redes OSPF: {ospf_networks}")


    # Extraer direcciones IP conectadas al equipo
    redes_conectadas = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', resultados['ips_propias'])
    print(f"Redes conectadas: {redes_conectadas}")

    # Determinar la IP conectada al ISP
    ip_firewall_a_cpe = find_network_in_range( redes_conectadas,host_vars['red_interna_paso_vpn'])

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


    parametros['redes_compartir']= convertir_cidr_a_diccionario(ospf_networks)


    #se obtiene el dispositivo que funcionara como hub de la vpn
    parametros['hub_vpn']=host_vars['groups'][grupo_aplicado][0]



    return parametros





def obterner_datos_cpe_nat_vpn_netmiko(host,parametros,host_vars,grupo_aplicado):
    """
        Obtiene información del dispositivo CPE utilizando Netmiko y realiza configuraciones basadas en los datos obtenidos.
        Args:
            host (str): Dirección IP o nombre del host del dispositivo.
            parametros (dict): Diccionario con parámetros de configuración.
            host_vars (dict): Variables del host, incluyendo nombres de grupos y miembros.
            grupo_aplicado (str): Nombre del grupo aplicado.
        Returns:
            dict: Parámetros actualizados con la información obtenida.
        Pasos:
            1. Ejecuta comandos en el dispositivo para obtener rutas conectadas, tabla de enrutamiento y vecinos OSPF.
            2. Extrae las redes conectadas y solicita al usuario elegir una si no se ha especificado previamente.
            3. Valida la dirección IP elegida.
            4. Extrae el gateway predeterminado de la tabla de enrutamiento y lo ajusta.
            5. Filtra las redes que contienen el gateway predeterminado.
            6. Extrae la IP del vecino OSPF.
            7. Actualiza los parámetros con la información obtenida.
            8. Guarda la información en las variables del grupo correspondiente.
        Raises:
            ValueError: Si la dirección IP elegida no es válida o no se encuentra un gateway en la tabla de enrutamiento.
    """


        # Ejecutar los comandos y obtener los resultados
    diccionario = lectura_datos_netmiko(host, ["show ip route connected", "show ip route", "show ip ospf neighbor"], ["route_connected", "routing_table", "ospf_neighbor"])

    # 1. Resultado de 'show ip route connected'
    resultado_route_connected = diccionario["route_connected"]

    # 2. Extraer todas las redes conectadas
    redes_conectadas = re.findall(r'C\s+([0-9.]+/[0-9]+)', resultado_route_connected)


    if not parametros['mismo_formato_red']:

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




    # 4. Validar la dirección IP elegida
    if ip_elegida not in redes_conectadas:
        raise ValueError(f"La dirección IP elegida no es válida. Debe ser una de las siguientes: {redes_conectadas}")

    print(f"La dirección IP elegida es: {ip_elegida}")

    # 5. Resultado de 'show ip route'
    routing_table_output = diccionario["routing_table"]


    # 6. Extraer gateway de la ruta predeterminada
    default_gateway_match = re.search(r'S\*\s+0\.0\.0\.0/0\s+\[\d+/\d+\]\s+via\s+([0-9.]+)', routing_table_output)
    default_gateway = default_gateway_match.group(1) if default_gateway_match else None
    #se pone una ip  diferente al equipo a tener problemas con los dispsotiivos en la version
    default_gateway=sumar_a_ip(default_gateway, 13)
    if not default_gateway:
        raise ValueError("No se encontró un gateway en la salida de la tabla de enrutamiento.")

    # 7. Extraer las redes y sus interfaces
    networks_and_interfaces_raw = re.findall(r'([0-9.]+/[0-9]+).* (GigabitEthernet\S+)', routing_table_output)
    # 8. Filtrar redes que contienen el gateway predeterminado
    networks_and_interfaces = find_network_for_gateway(default_gateway, networks_and_interfaces_raw)
    # 9. Resultado de 'show ip ospf neighbor'
    ospf_neighbor_output = diccionario["ospf_neighbor"]

    # 10. Extraer la IP del vecino OSPF
    neighbor_ip_match = re.search(r'^\s*\S+\s+\d+\s+\S+\s+\S+\s+([0-9.]+)\s+\S+', ospf_neighbor_output, re.MULTILINE)
    print(ospf_neighbor_output)
    neighbor_ip = neighbor_ip_match.group(1) if neighbor_ip_match else None

    print("********************************")

    print(f"La dirección IP del vecino OSPF es: {neighbor_ip}")
    print(f"  La ip eleguida es ip_elegida_final: {cidr_to_network_and_wildcard(ip_elegida)}")
    print(f"  La ip gateway es default_gateway_final: {default_gateway}")
    print(f"{networks_and_interfaces[1] }")

    parametros['red_interna']=[ {
        "ip": cidr_to_network_and_wildcard(ip_elegida),
        "destino": "any",
    }
    ]

    parametros['interfaz_red']= networks_and_interfaces[1]
    parametros['origen']="inside"
    parametros['ip_fw']=[neighbor_ip]
    parametros['ip_cpe']=default_gateway
    #guardar dicha informacion en las variables del grupo
    grupo_zona = next((grupo for grupo in host_vars['group_names'] if grupo.startswith('zona')), None)
    print(f"Grupo de zona: {grupo_zona}")
    create_or_update_group_vars_file(grupo_zona,{"red_interna_paso_vpn" : ip_elegida})
    for firewall in host_vars['groups']['firewalls']:
        for integrante_zona in host_vars['groups'][grupo_zona]:
            if firewall == integrante_zona:

                create_or_update_group_vars_file("firewalls",{"ip_recepcion_vpn"+str(firewall): default_gateway})

                return parametros



