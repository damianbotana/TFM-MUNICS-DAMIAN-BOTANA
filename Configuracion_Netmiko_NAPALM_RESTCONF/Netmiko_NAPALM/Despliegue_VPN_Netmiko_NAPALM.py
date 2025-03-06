from .Comandos_Cisco_parametrizados.Comandos_paremetrizados_configuracion_VPN import definicion_crypto_map,crear_autoridad_certificadora,definicion_ca_que_se_utiliza,crear_key_ring,crear_perfil_ikev2,creacion_propuesta_ikev2,crear_politica_ikev2,crear_perfil_ipsec,crear_tunel_spoke,crear_tunel_hub,crear_red_bgp,crear_red_ospf_bgp,obtener_clave_y_ip,traduccion_direcciones_nat,traduccion_nat_estatica

def creacion_autoridad_certificadora_completo(host,lista_hosts,parametros,aplicacion_equipos_herramienta):

    """
        Crea una autoridad certificadora completa y aplica los comandos necesarios en los equipos especificados.

        Args:
            host (dict): Diccionario con la información del host, incluyendo el nombre del equipo.
            lista_hosts (list): Lista de hosts a los que se aplicarán los comandos.
            organizacion (str): Nombre de la organización para la autoridad certificadora.
            aplicacion_equipos_herramienta (function): Función que aplica los comandos en los equipos.

        Returns:
            None
    """
    hostname_equipo_aplicado=host.pop('nombre_equipo')
    lista_comandos_con_interaccion=["no shutdown"]
    lista_experados=["assword:"]
    lista_respuestas=[[parametros['password_ca'],parametros['password_ca']]]

    comandos=crear_autoridad_certificadora(hostname_equipo_aplicado,parametros['subname'])


    aplicacion_equipos_herramienta(host,comandos,lista_comandos_con_interaccion,lista_experados,lista_respuestas)




def aplicacion_ca_equipos(host, lista_hosts,parametros,aplicacion_equipos_herramienta):
    hostname_equipo_aplicado=host.pop('nombre_equipo')
    lista_comandos_con_interaccion=[f"crypto pki authenticate {hostname_equipo_aplicado}",f"crypto pki enroll {hostname_equipo_aplicado}"]
    lista_experados=["yes/no","assword:"]
    #estes datos posteriormente se cogen de un fichero
    lista_respuestas=[["yes"],[parametros['password_ca'],parametros['password_ca'],"no","no","yes"]]



    comandos=definicion_ca_que_se_utiliza(hostname_equipo_aplicado,"http://"+parametros['ip_ca'],parametros['subname'])
    #print(comandos)

    aplicacion_equipos_herramienta(host,comandos,lista_comandos_con_interaccion,lista_experados,lista_respuestas)



def aplicacacion_nat_vpn(host, lista_hosts, parametros, aplicacion_equipos_herramienta):


    hostname_equipo_aplicado = host.pop('nombre_equipo')
    id_acl = "123"
    lista_nat_equipos = []
    # parametros[hostname_equipo_aplicado]['red_interna'] se obtiene de un diccionario con la red interna que se quiere traducir para dicho equipo viene por parametro

    comandos = traduccion_direcciones_nat(id_acl, parametros['red_interna'], parametros['interfaz_red'], parametros['origen'])
    for ip_firewall in parametros['ip_fw']:

        lista_nat_equipos.append({
            'flujo': 'inside',
            'tipo_trafico': 'udp',
            'direccion_interna': ip_firewall,
            'puerto_interno': '500',
            'direccion_externa': parametros['ip_cpe'],
            'puerto_externo': '500',
        })
        lista_nat_equipos.append({
            'flujo': 'inside',
            'tipo_trafico': 'udp',
            'direccion_interna': ip_firewall,
            'puerto_interno': '4500',
            'direccion_externa': parametros['ip_cpe'],
            'puerto_externo': '4500',
        })

    comandos += traduccion_nat_estatica(lista_nat_equipos)

    # print(comandos)

    aplicacion_equipos_herramienta(host, comandos, [], [], [])


def vpn_dispositivos_despues_nat(host, lista_hosts, parametros, aplicacion_equipos_herramienta):


    hostname_equipo_aplicado = host.pop('nombre_equipo')
    lista_vecinos_bgp = []
    nombre_perfil = "ikev2_profile"
    nombre_ipsec = "ikev2_ipsec_profile"
    comandos = ""

    if parametros["tipo_autenticacion"] == "rsa-sig":
        metodo_autenticacion = "certificate"
        autenticacion_ikev2 = f"pki trustpoint {hostname_equipo_aplicado}"
        comandos = definicion_crypto_map(hostname_equipo_aplicado, parametros['subname'])
    elif parametros["tipo_autenticacion"] == "pre-share":
        lista_elementos2 = [{"nombre": host2['nombre'], "direccion": parametros[host2['nombre']]['ip_cpe']} for host2 in lista_hosts]
        comandos = crear_key_ring(hostname_equipo_aplicado, lista_elementos2, parametros["ip_vpn"])
        metodo_autenticacion = "fqdn"
        autenticacion_ikev2 = "keyring local KEYRING"

    comandos += crear_perfil_ikev2(nombre_perfil, hostname_equipo_aplicado, lista_hosts, metodo_autenticacion, parametros["tipo_autenticacion"], autenticacion_ikev2)
    comandos += creacion_propuesta_ikev2("ikev2_proporsal", parametros['encriptado'], parametros['integridad'], parametros['grupo_dif'])
    comandos += crear_politica_ikev2("ikev2_policy", "ikev2_proporsal")
    comandos += crear_perfil_ipsec(nombre_ipsec, nombre_perfil)

    if parametros['hub_vpn'] != hostname_equipo_aplicado:
        equipo_hub = {"nombre_equipo": parametros['hub_vpn'], "direccion": parametros[parametros['hub_vpn']]['ip_cpe']}
        comandos += crear_tunel_spoke(hostname_equipo_aplicado, parametros["ip_vpn"], equipo_hub, parametros['ip_interna'], nombre_ipsec, len(lista_hosts))
        ospf_id = parametros[hostname_equipo_aplicado]['bgp_id']
        ospf_id_rival = parametros[parametros['hub_vpn']]['bgp_id']
        clave_equipo_peer, ip_vpn_peer = obtener_clave_y_ip("claves.json", parametros['hub_vpn'], parametros["ip_vpn"])
        lista_vecinos_bgp.append({"neighbor": ip_vpn_peer, "remote_as": ospf_id_rival})
    else:
        lista_elementos = [{"nombre": host_rival['nombre'], "direccion": parametros[host_rival['nombre']]['ip_cpe']} for host_rival in lista_hosts]
        comandos += crear_tunel_hub(parametros['hub_vpn'], parametros["ip_vpn"], parametros['ip_interna'], lista_elementos, nombre_ipsec)
        ospf_id = parametros[hostname_equipo_aplicado]['bgp_id']
        for host_rival in lista_elementos:
            ospf_id_rival = parametros[host_rival['nombre']]['bgp_id']
            clave_equipo_peer, ip_vpn_peer = obtener_clave_y_ip("claves.json", host_rival['nombre'], parametros["ip_vpn"])
            lista_vecinos_bgp.append({"neighbor": ip_vpn_peer, "remote_as": ospf_id_rival})

    comandos += crear_red_bgp(ospf_id, parametros['redes_compartir'], lista_vecinos_bgp)
    comandos += crear_red_ospf_bgp(ospf_id)
    comandos += "ip dhcp support tunnel unicast\n"

    aplicacion_equipos_herramienta(host, comandos, [], [], [])
