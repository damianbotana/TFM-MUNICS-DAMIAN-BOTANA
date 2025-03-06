import os

import json
import uuid
import ipaddress
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


def _crear_peer_key_ring(nombre_key_ring, direccion_peer, pre_shared_key_local, pre_shared_key_remote):
    return f"""peer {nombre_key_ring}
    !direccion publica de {nombre_key_ring}
    address {direccion_peer}
    !definicion de las claves precompartidas de la VPN
    pre-shared-key local {pre_shared_key_local}
    pre-shared-key remote {pre_shared_key_remote}
"""

def crear_key_ring(host_aplicado, lista_hosts, base_vpn_ip):
    '''
    host_aplicado: nombre del equipo donde se aplican las configuraciones
    lista_hosts: lista de diccionarios con nombre del equipo y dirección ip
    base_vpn_ip: dirección IP base para asignar la primera VPN IP
    return: string con la configuracion de los keyrings del equipo en cuestión
    '''
    clave_equipo_aplicado, ip_vpn_aplicado = obtener_clave_y_ip(ruta_fichero, host_aplicado, base_vpn_ip)
    creacion_key_ring = "\ncrypto ikev2 keyring KEYRING\n"

    for host in lista_hosts:
        # Obtener o asignar clave y VPN IP para el peer
        clave_equipo_peer, ip_vpn_peer = obtener_clave_y_ip(ruta_fichero, host['nombre'], base_vpn_ip)
        creacion_key_ring += _crear_peer_key_ring(host['nombre'], host['direccion'], clave_equipo_aplicado, clave_equipo_peer)

    return creacion_key_ring

def definicion_crypto_map(nombre_crytp_map,subjecname):
    return f"""
    crypto pki certificate map {nombre_crytp_map} 10
    subject-name co {subjecname}
    """

def crear_red_bgp(identificador_red, redes, neighbors):
    """
    Crea la configuración de una red BGP.

    Args:
        identificador_red (int): El identificador del sistema autónomo (AS) para la red BGP.
        redes (list): Una lista de diccionarios que contienen las redes a anunciar.
                      Cada diccionario debe tener las claves 'direccion' y 'mascara'.
        neighbors (list): Una lista de diccionarios que contienen los vecinos BGP.
                          Cada diccionario debe tener las claves 'neighbor' y 'remote_as'.

    Returns:
        str: La configuración BGP en formato de cadena de texto.
    """
    comando = f"router bgp {identificador_red}\n"
    for red in redes:
        comando += f"network {red['direccion']} mask {red['mascara']}\n"
    for neighbor in neighbors:
        comando += f"neighbor {neighbor['neighbor']} remote-as {neighbor['remote_as']}\n"
    return comando


def crear_red_ospf_bgp(identificador):
    """
    Genera la configuración para redistribuir las redes obtenidas mediante BGP en OSPF.

    Args:
        identificador (int): El identificador del proceso BGP que se va a redistribuir en OSPF.

    Returns:
        str: La configuración en formato de cadena para redistribuir BGP en OSPF.
    """
    return f"""
    router ospf 1
    redistribute bgp {identificador}
    """


def crear_perfil_ikev2(nombre_perfil, host_aplicado, lista_hosts, metodo_identificacion, tipo_autenticacion, configuraciones_extra):
    '''
    Crea la configuración de un perfil IKEv2 para un equipo específico.
    Args:
        nombre_perfil (str): Nombre del perfil IKEv2.
        host_aplicado (str): Nombre del equipo donde se aplican las configuraciones.
        lista_hosts (list): Lista de diccionarios con el nombre del equipo y su dirección IP.
        metodo_identificacion (str): Método de identificación (por ejemplo, 'address', 'fqdn', 'certificate').
        tipo_autenticacion (str): Tipo de autenticación (por ejemplo, 'rsa-sig', 'pre-share').
        configuraciones_extra (str): Configuraciones adicionales que se deben agregar al perfil.
    Returns:
        str: Cadena con la configuración del perfil IKEv2 para el equipo en cuestión.
    '''
    creacion_perfil_ikev2 = f"""
    crypto ikev2 profile {nombre_perfil}
    """

    for host in lista_hosts:
        if "certificate" == metodo_identificacion:
            creacion_perfil_ikev2 += f"\n match certificate {host_aplicado}\n"
        else:
            creacion_perfil_ikev2 += f"\n match identity remote {metodo_identificacion} {host['nombre']}\n"

    creacion_perfil_ikev2 += f"""
    identity local fqdn {host_aplicado}
    authentication local {tipo_autenticacion}
    authentication remote {tipo_autenticacion}
    {configuraciones_extra}
    """
    return creacion_perfil_ikev2

def creacion_propuesta_ikev2(nombre_prpuesta, algortimo_cifrado, algoritmo_integrida, grupo_interncambio_claves):
    """
    Genera una configuración de propuesta IKEv2 para un dispositivo Cisco.

    Args:
        nombre_prpuesta (str): El nombre de la propuesta IKEv2.
        algortimo_cifrado (str): El algoritmo de cifrado a utilizar (por ejemplo, aes-256).
        algoritmo_integrida (str): El algoritmo de integridad (PRF) a utilizar (por ejemplo, sha256).
        grupo_interncambio_claves (str): El grupo de intercambio de claves DH a utilizar (por ejemplo, 14).

    Returns:
        str: Una cadena de texto con la configuración de la propuesta IKEv2.
    """
    return f"""
    crypto ikev2 proposal {nombre_prpuesta}
    encryption {algortimo_cifrado}
    prf {algoritmo_integrida}
    group {grupo_interncambio_claves}
    """

def crear_politica_ikev2(nombre_politica, nombre_proporsal):
    """
    Genera la configuración de una política IKEv2 para aplicar la propuesta creada anteriormente.

    Args:
        nombre_politica (str): El nombre de la política IKEv2.
        nombre_proporsal (str): El nombre de la propuesta IKEv2.

    Returns:
        str: La configuración de la política IKEv2 en formato de cadena.
    """
    return f"""
    crypto ikev2 policy {nombre_politica}
    proposal {nombre_proporsal}
    """

def crear_perfil_ipsec(nombre_perfil_ipsec, nombre_perfil_ikev2):
    """
    Crea un perfil IPsec con el nombre y perfil IKEv2 especificados.

    Args:
        nombre_perfil_ipsec (str): El nombre del perfil IPsec a crear.
        nombre_perfil_ikev2 (str): El nombre del perfil IKEv2 a asociar con el perfil IPsec.

    Returns:
        str: Comando de configuración para crear el perfil IPsec con el perfil IKEv2 asociado.
    """
    return f"""
    crypto ipsec profile {nombre_perfil_ipsec}
    set ikev2-profile {nombre_perfil_ikev2}
    """

def _crear_tunel_indivual(identificador_tunel, direccion_red_vpn, direccion_router, direccion_dispositivo, nombre_perfil_ipsec):
    """
    Crea la configuración de un túnel individual para una VPN en un dispositivo Cisco.
    Args:
        identificador_tunel (int): El identificador único del túnel.
        direccion_red_vpn (str): La dirección IP de la red VPN.
        direccion_router (str): La dirección IP del router al que se quiere conectar.
        direccion_dispositivo (str): La dirección IP del dispositivo al que se quiere establecer la VPN.
        nombre_perfil_ipsec (str): El nombre del perfil IPSec a utilizar para la protección del túnel.
    Returns:
        str: La configuración del túnel en formato de cadena.
    """
    creacion_tunel = f"""
    interface Tunnel{identificador_tunel}
        ! Red de la vpn
        ip address {direccion_red_vpn}

        ! IP del router al que se quiere conectar
        tunnel source {direccion_router}

        ! Dirección IP al dispositivo al que nos queremos establecer la vpn
        tunnel destination {direccion_dispositivo}

        ! Utilización de smart default y el perfil creado anteriormente
        tunnel protection ipsec profile {nombre_perfil_ipsec}


    """
    return creacion_tunel

def _crear_tunel_mgre_hub(identificador_tunel, direccion_red_vpn, direccion_router, nombre_perfil_ipsec,clave_autenticacion):
    creacion_tunel = f"""
    interface Tunnel{identificador_tunel}
        ! Red de la vpn
        ip address {direccion_red_vpn}

        ! IP del router al que se quiere conectar
        tunnel source {direccion_router}



        ! Utilización de smart default y el perfil creado anteriormente
        tunnel protection ipsec profile {nombre_perfil_ipsec}

        ip nhrp authentication {clave_autenticacion}
        ip nhrp network-id 1
        tunnel mode gre multipoint
        ip nhrp map multicast dynamic


    """
    return creacion_tunel

def _crear_tunel_mgre_spoke(identificador_tunel, direccion_red_vpn,direccion_red_vpn_destino, direccion_router, direccion_dispositivo, nombre_perfil_ipsec,clave_autenticacion):
    creacion_tunel = f"""
    interface Tunnel{identificador_tunel}
        ! Red de la vpn
        ip address {direccion_red_vpn}

        ! IP del router al que se quiere conectar
        tunnel source {direccion_router}

        tunnel destination {direccion_dispositivo}

        ! Utilización de smart default y el perfil creado anteriormente
        tunnel protection ipsec profile {nombre_perfil_ipsec}

        ip nhrp authentication {clave_autenticacion}
        ip nhrp network-id 1

        ip nhrp  nhs {direccion_red_vpn_destino} nbma {direccion_dispositivo} multicast

    """
    return creacion_tunel


def crear_tunel_hub(host_aplicado,red_vpn,ip_interna,lista_hosts,nombre_perfil_ipsec):

    """
        Crea la configuración de túneles VPN para un equipo específico.
        Args:
            host_aplicado (str): Nombre del equipo donde se aplican las configuraciones.
            red_vpn (str): Red VPN utilizada.
            ip_interna (str): Dirección IP origen .
            lista_hosts (list): Lista de diccionarios con el nombre del equipo y la dirección IP destinos.
            nombre_perfil_ipsec (str): Nombre del perfil IPSec.
        Returns:
            str: Configuración de los túneles del equipo en cuestión.
        """
    '''
    host_aplicado: nombre del equipo donde se aplican las configuraciones
    lista_hosts: lista de diccionarios con  nombre equipo y direccion ip
    return: string con la configuracion de los tunel del equipo en cuestion
    '''


    creacion_tunel=""
    #se va incluir en dicha lista todos los host vecnos en caso de ser más que uno significa que va a tener más de un
    #vecino y por lo tanto se aplica mgre
    #caso tunel estatico
    if len(lista_hosts)<2:
        for host in lista_hosts:
            clave_equipo_peer, ip_vpn_peer=obtener_clave_y_ip(ruta_fichero, host_aplicado, red_vpn)
            ip_vpn_peer=ip_vpn_peer+" "+str("255.255.255.252")

            creacion_tunel+=_crear_tunel_indivual(0,ip_vpn_peer,ip_interna,host['direccion'],nombre_perfil_ipsec)
    #caso de mgre
    else:
         clave_equipo_peer, ip_vpn_peer=obtener_clave_y_ip(ruta_fichero, host_aplicado,red_vpn)
         ip_vpn_peer=ip_vpn_peer+" "+str("255.255.255.0")
         #si me aburro cambiar la contraseña por defecto
         creacion_tunel+=_crear_tunel_mgre_hub(0,ip_vpn_peer,ip_interna,nombre_perfil_ipsec,"DMVPN")
    return creacion_tunel


def crear_tunel_spoke(host_aplicado, red_vpn, equipo_hub, ip_interna, nombre_perfil_ipsec,numero_elementos):
    """
    Crea la configuración de un túnel IPSec para un equipo spoke en una red VPN.
    Args:
        host_aplicado (str): Nombre del equipo donde se aplican las configuraciones.
        red_vpn (str): Nombre de la red VPN.
        equipo_hub (dict): Diccionario con la información del equipo hub, incluyendo 'nombre_equipo' y 'direccion'.
        ip_interna (str): Dirección IP interna del equipo spoke.
        nombre_perfil_ipsec (str): Nombre del perfil IPSec a utilizar.
        numero_elementos (int): Número de elementos en la lista de hosts.
    Returns:
        str: Configuración del túnel IPSec para el equipo spoke.
    """
    creacion_tunel = ""
    clave_equipo_peer, ip_vpn_peer = obtener_clave_y_ip(ruta_fichero,host_aplicado, red_vpn)

    if numero_elementos<2:
        # se obtiene la ip
        ip_vpn_peer=ip_vpn_peer+" "+str("255.255.255.252")
        creacion_tunel += _crear_tunel_indivual(0, ip_vpn_peer, ip_interna, equipo_hub['direccion'], nombre_perfil_ipsec)
    else:
        ip_vpn_peer=ip_vpn_peer+" "+str("255.255.255.0")
        clave_equipo_peer, ip_vpn_peer_destino = obtener_clave_y_ip(ruta_fichero, equipo_hub['nombre_equipo'], red_vpn)

        creacion_tunel += _crear_tunel_mgre_spoke(0, ip_vpn_peer,ip_vpn_peer_destino, ip_interna, equipo_hub['direccion'], nombre_perfil_ipsec,"DMVPN")
    return creacion_tunel

def traduccion_nat_estatica(lista_comandos):
    """
    Genera configuraciones de traducción NAT estática a partir de una lista de comandos.
    Args:
        lista_comandos (list): Lista de diccionarios, donde cada diccionario contiene las claves:
            - 'flujo' (str): Tipo de flujo (por ejemplo, 'inside' o 'outside').
            - 'tipo_trafico' (str): Tipo de tráfico (por ejemplo, 'tcp' o 'udp').
            - 'direccion_interna' (str): Dirección IP interna.
            - 'puerto_interno' (str): Puerto interno.
            - 'direccion_externa' (str): Dirección IP externa.
            - 'puerto_externo' (str): Puerto externo.
    Returns:
        str: Cadena de texto con las configuraciones de traducción NAT estática generadas.
    """
    traducciones_nat=""
    for comando in lista_comandos:

        traducciones_nat+=f"ip nat {comando['flujo']} source static {comando['tipo_trafico']} {comando['direccion_interna']} {comando['puerto_interno']} {comando['direccion_externa']} {comando['puerto_externo']}\n"
    return traducciones_nat

def traduccion_direcciones_nat(id_acl,lista_ips,interfaz_red,origen):

    """
        Genera las configuraciones de traducción de direcciones NAT para una lista de IPs.
        Args:
            id_acl (str): Identificador de la lista de control de acceso (ACL).
            lista_ips (list): Lista de diccionarios con las IPs y sus destinos asociados.
            interfaz_red (str): Nombre de la interfaz de red a utilizar para la traducción NAT.
            origen (str): Origen de la lista de control de acceso (ACL).
        Returns:
            str: Configuración de traducción de direcciones NAT en formato de texto.
    """
    traducciones_nat=""
    for ip_diccionario in lista_ips:
        traducciones_nat+=f"access-list {id_acl} permit ip {ip_diccionario['ip']} {ip_diccionario['destino']}\n"

    traducciones_nat+=f"ip nat {origen} source list {id_acl} interface {interfaz_red} overload\n"
    return traducciones_nat

#la siguiente funcion tiene que tener un prompt para contestar con la contraseña
def crear_autoridad_certificadora(nombre_autoridad, organizacion):
    """
    Crea una configuración de autoridad certificadora (CA) para un equipo de  Cisco.

    Args:
        nombre_autoridad (str): El nombre de la autoridad certificadora.
        organizacion (str): El nombre de la organización.

    Returns:
        str: Una cadena de texto con la configuración de la autoridad certificadora.
    """
    return f"""
    ip http server
    !contexto
    crypto pki server {nombre_autoridad}
    issuer-name CN={nombre_autoridad},O={organizacion},C=ES
    grant auto
    lifetime certificate 3650
    lifetime ca-certificate 3650
    """

#la siguiente funcion tiene un prompt para contestar con la contraseña
def definicion_ca_que_se_utiliza(nombre_equipo, direccion_ca, subjectname):
    """
    Genera una configuración de trustpoint para un equipo de red Cisco.

    Args:
        nombre_equipo (str): El nombre del equipo de red.
        direccion_ca (str): La dirección URL del servidor de la Autoridad de Certificación (CA).
        subjectname (str): El nombre del sujeto que se incluirá en el certificado.

    Returns:
        str: Una cadena de texto con la configuración del trustpoint.
    """
    return f"""
    !contexto
    crypto pki trustpoint {nombre_equipo}

    ! Obtención del ceritificado del servidor ISP
    enrollment url {direccion_ca}

    ! Inclusión del subjectname al certificado creado
    subject-name cn={subjectname}
    """
