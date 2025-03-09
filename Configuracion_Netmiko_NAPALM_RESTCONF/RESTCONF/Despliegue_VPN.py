
from funciones_auxiliares  import obtener_clave_y_ip,create_or_update_group_vars_file,obtener_parametros_vpn,sumar_a_ip,cidr_to_network_and_wildcard,cidr_to_network_and_wildcard_tuple
import json
from RESTCONF.Configuraccion_acceso_dispositivos_RESTCONF import obtener_informacion_restconf
import ipaddress
import sys
sys.path.append("..") # Adds higher directory to python modules path.


#------------------------------------------------------Obtención informacion-------------------------
def obtener_datos_firewall_nat_vpn_restconf(host,parametros,host_vars,grupo_aplicado):

    """
        Obtiene datos de configuración de firewall, NAT y VPN utilizando RESTCONF.
        Args:
            host (dict): Diccionario con información del host, incluyendo 'direccion', 'username', 'password' y 'nombre_equipo'.
            parametros (dict): Diccionario donde se almacenarán los parámetros obtenidos.
            host_vars (dict): Diccionario con variables del fichero de ansible.
            grupo_aplicado (str): Nombre del grupo aplicado dicha configuracion
        Returns:
            dict: Diccionario actualizado con los parámetros de configuración.
        El flujo de la función es el siguiente:
        1. Obtiene información de rutas OSPF desde el dispositivo utilizando RESTCONF.
        2. Filtra las rutas OSPF para obtener aquellas que no terminan en '/32' o '/0'.
        3. Actualiza el diccionario 'parametros' con las redes a compartir.
        4. Asigna la IP interna del equipo y el hub VPN.
        5. Itera sobre los firewalls en 'host_vars' para asignar IPs de recepción VPN y BGP IDs.
        Notas:
        - La función asume que 'obtener_informacion_restconf' es una función auxiliar que realiza la solicitud RESTCONF.
        - Las claves en 'host_vars' deben estar correctamente definidas para evitar errores.
    """

    parametros.update(obtener_parametros_vpn(host_vars))

    # Obtener información de rutas desde el dispositivo
    data = obtener_informacion_restconf(
        f"https://{host['direccion']}:443/restconf/data/ietf-routing:routing-state/routing-instance=default/ribs/rib=ipv4-default/routes/route",
        host['username'], host['password']
    )

    # Filtrar las rutas OSPF
    redes_ospf = [
        route['destination-prefix'] for route in data['ietf-routing:route']
        if route['source-protocol'] == 'ietf-ospf:ospfv2' and not route['destination-prefix'].endswith(('/32', '/0'))
    ]

    if host['nombre_equipo'] not in parametros:
        parametros[host['nombre_equipo']] = {}
    # Convertir las redes OSPF a diccionario
    parametros[host['nombre_equipo']]['redes_compartir'] = [
        {
            "direccion": str(ipaddress.ip_network(red, strict=False).network_address),
            "mascara": str(ipaddress.ip_network(red, strict=False).netmask)
        }
        for red in redes_ospf
    ]




    # Asignar IP interna y hub VPN
    parametros[host['nombre_equipo']]['ip_interna'] = host_vars['ip_fw_cpe']
    parametros['hub_vpn'] = host_vars['groups'][grupo_aplicado][0]




    # Asignar IPs de recepción VPN y BGP IDs para firewalls
    for i, firewall in enumerate(host_vars['groups'][grupo_aplicado]):
        ip_recepcion_key = f'ip_recepcion_vpn{firewall}'
        if firewall not in parametros:
                parametros[firewall] = {}
        if ip_recepcion_key in host_vars:

            parametros[firewall]['ip_cpe'] = host_vars[ip_recepcion_key]
        else:
            print(f"Clave '{ip_recepcion_key}' no encontrada en host_vars")
        bpg_id_firewall=f'bgp_id_{firewall}'
        #en caso que tenga un valor se coge dicho valor para el id del bgp y  en caso contrario se le asigna un valor por defecto
        if bpg_id_firewall in host_vars:
            parametros[firewall]['bgp_id'] = host_vars[bpg_id_firewall]
        else:
            if 'bgp_id_actual' not  in host_vars:
                create_or_update_group_vars_file("all", {'bgp_id_actual': 65000})
                parametros[firewall]['bgp_id']=65000 + 1
            else:
                parametros[firewall]['bgp_id'] = host_vars['bgp_id_actual'] + i


            create_or_update_group_vars_file(grupo_aplicado, {f'bgp_id_{firewall}': parametros[firewall]['bgp_id']})
            create_or_update_group_vars_file("all", {'bgp_id_actual':parametros[firewall]['bgp_id'] })



    return parametros

def obtener_datos_cpe_nat_restconf(host, parametros, host_vars, grupo_aplicado):
    """
    Obtiene información de rutas y configuraciones de un dispositivo CPE utilizando RESTCONF.

    Args:
        host (dict): Diccionario con la información del host, incluyendo 'direccion', 'username', 'password', y 'nombre_equipo'.
        parametros (dict): Diccionario con parámetros adicionales necesarios para la configuración.
        host_vars (dict): Diccionario con variables del host, incluyendo 'group_names' y 'groups'.
        grupo_aplicado (str): Nombre del grupo aplicado.

    Returns:
        dict: Diccionario actualizado con la información de configuración del CPE.
        None: Si no se encuentra la ruta predeterminada.
    """

    # Obtener información de rutas desde el dispositivo
    data = obtener_informacion_restconf(
        f"https://{host['direccion']}:443/restconf/data/ietf-routing:routing-state/routing-instance=default/ribs/rib=ipv4-default/routes/route",
        host['username'], host['password']
    )

    # Buscar la ruta predeterminada (0.0.0.0/0)
    default_route = next((route for route in data['ietf-routing:route'] if route['destination-prefix'] == '0.0.0.0/0'), None)
    redes_conectadas = [route['destination-prefix'] for route in data['ietf-routing:route'] if route['source-protocol'] == 'ietf-routing:direct' and not route['destination-prefix'].endswith('/32')]

    if default_route:
        # Extraer la IP del gateway
        ip_gateway = default_route['next-hop']['next-hop-address']

        # Solicitar entrada del usuario si no se ha definido el formato de red
        if not parametros.get('mismo_formato_red'):
            ip_elegida = input(f"Escribe la opción que deseas usar (elige una de las siguientes IPs: {redes_conectadas}): ")
            mismo_formato_red = input("¿La red tiene el mismo formato para el resto de dispositivos? (s/n): ")
            while mismo_formato_red not in ["s", "n"]:
                mismo_formato_red = input("¿La red tiene el mismo formato para el resto de dispositivos? (s/n): ")

            if mismo_formato_red == "s":
                parametros['mismo_formato_red'] = True
                parametros['ip_elegida'] = ip_elegida
        else:
            ip_elegida = parametros['ip_elegida']

        # Buscar la red que contiene el gateway y obtener la interfaz y la IP del CPE
        for red in data['ietf-routing:route']:
            network = ipaddress.ip_network(red['destination-prefix'], strict=False)
            if ipaddress.ip_address(ip_gateway) in network and network != ipaddress.ip_network('0.0.0.0/0'):
                interface = red['next-hop']['outgoing-interface']
                ip_cpe_data = obtener_informacion_restconf(
                    f"https://{host['direccion']}:443/restconf/data/ietf-interfaces:interfaces/interface={interface}",
                    host['username'], host['password']
                )
                vecino_data = obtener_informacion_restconf(
                    f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-ospf-oper:ospf-oper-data/ospf-state/ospf-instance?fields=ospf-area/ospf-interface/ospf-neighbor/address",
                    host['username'], host['password']
                )

                # Extraer la IP del vecino OSPF
                for vecino_ospf in vecino_data['Cisco-IOS-XE-ospf-oper:ospf-instance'][0]['ospf-area'][0]['ospf-interface']:
                    if ipaddress.ip_address(vecino_ospf['ospf-neighbor'][0]['address']) in ipaddress.ip_network(ip_elegida, strict=False):
                        ip_cpe = sumar_a_ip(ip_cpe_data['ietf-interfaces:interface']['ietf-ip:ipv4']['address'][0]['ip'], 13)
                        network, wildcard = cidr_to_network_and_wildcard_tuple(ip_elegida)

                        # Actualizar parámetros
                        parametros['red_interna'] = [{
                            "ip": cidr_to_network_and_wildcard(ip_elegida),
                            "destino": "any",
                        }]
                        if host['nombre_equipo'] not in parametros:
                            parametros[host['nombre_equipo']] = {}
                        parametros[host['nombre_equipo']].update({
                            'interfaz_red': interface,
                            'origen': "inside",
                            'ip_fw': [vecino_ospf['ospf-neighbor'][0]['address']],
                            'ip_cpe': ip_cpe,
                            'nat_vpn': [{
                                "id_acl": 123,
                                "ip_nat": [{
                                    "ip": network,
                                    "mask": wildcard,
                                    "action": "permit",
                                    "protocol": "ip",
                                    'destination': "any"
                                }]
                            }]
                        })

                        # Guardar información en las variables del grupo
                        grupo_zona = next((grupo for grupo in host_vars['group_names'] if grupo.startswith('zona')), None)
                        create_or_update_group_vars_file(grupo_zona, {"red_interna_paso_vpn": ip_elegida})
                        create_or_update_group_vars_file(grupo_zona, {"ip_fw_cpe": vecino_ospf['ospf-neighbor'][0]['address']})

                        for firewall in host_vars['groups']['firewalls']:
                            if firewall in host_vars['groups'][grupo_zona]:
                                create_or_update_group_vars_file("firewalls", {"ip_recepcion_vpn" + str(firewall): ip_cpe})

                                return parametros
    return None


#-----------------------------------------------------------IMPLEMENTACION-----------------------------
def _transform_grupo_dif(grupo_dif):
    dh_group={
        "1": "one",
        "2": "two",
        "5": "five",
        "14": "fourteen",
        "15": "fifteen",
        "16": "sixteen",
        "19": "nineteen",
        "20": "twenty",
        "21": "twenty-one",
        "24": "twenty-four"
    }
    return dh_group[grupo_dif]


def _crear_peer_keyring(host,equipos_host,parametros):
    peers=[]
    clave_equipo_local, ip_vpn_local = obtener_clave_y_ip("claves.json", host['direccion'], parametros["ip_vpn"])


    for equipo in equipos_host:
        clave_equipo_remote, ip_vpn_remote = obtener_clave_y_ip("claves.json", equipo['direccion'], parametros["ip_vpn"])

        peers.append( {
                        "name": equipo['nombre'],
                        "address": {
                            "ipv4": {
                                "ipv4-address": parametros[equipo['nombre']]['ip_cpe']
                            }
                        },
                        "pre-shared-key": {
                            "local-option": {
                                "key": clave_equipo_local
                            },
                            "remote-option": {
                                "key": clave_equipo_remote
                            }
                        }
                    })
    return peers


def _obtener_neighboor_bgp(host,lista_hosts,parametros):
    lista_neighboor=[]
    if parametros['hub_vpn']!=host['nombre_equipo']:
        clave, ip_vpn=obtener_clave_y_ip("claves.json",str(parametros['hub_vpn']) , parametros["ip_vpn"])

        lista_neighboor.append({
                    "id": ip_vpn ,
                    "remote-as": parametros[parametros['hub_vpn']]['bgp_id']
        })
    else:
        for equipo in lista_hosts:
            clave, ip_vpn=obtener_clave_y_ip("claves.json", str(equipo['nombre']), parametros["ip_vpn"])

            lista_neighboor.append(
                {
                    "id": ip_vpn ,
                    "remote-as": parametros[equipo['nombre']]['bgp_id']
                }
            )
    return lista_neighboor

def definir_ipsec_perfil_resconf(host,lista_hosts,parametros,aplicacion_equipos_herramienta):

    data={
        "profile": [
      {
        "name": parametros['ipsec_name_profile'],
        "set": {
          "ikev2-profile": parametros['profile_ike_v2_name'],
        }
      }
    ]
    }
    data=json.dumps(data)
    print(data)
    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/crypto/ipsec",host['username'],host['password'],data)


def creacion_nat_puerto(host,lista_hosts,parametros,aplicacion_equipos_herramienta):

    lista_nat_equipos=[]
    for ip_interna in parametros[host['nombre_equipo']]['ip_fw']:
        lista_nat_equipos.append(
            {
               "local-ip": ip_interna,
               "global-ip": parametros[host['nombre_equipo']]['ip_cpe'],
            }
        )
    data={
        "Cisco-IOS-XE-nat:nat-static-transport-list": lista_nat_equipos
    }
    data=json.dumps(data,indent=2)
    print(data)
    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/ip/nat/inside/source/static",host['username'],host['password'],data)


    return parametros




def acl_creacion_resconf(host,lista_hosts,parametros,aplicacion_equipos_herramienta):

    lista_acl=[]
    cont=10
    for nat_vpn in parametros[host['nombre_equipo']]['nat_vpn']:

        for conjunto_acl in nat_vpn['ip_nat']:

            ace_rule = {
                "sequence": cont,
                "ace-rule": {
                    "action": conjunto_acl['action'],
                    "protocol": conjunto_acl['protocol'],
                    "ipv4-address": conjunto_acl['ip'],
                    "mask": conjunto_acl['mask']
                }
            }

            # Verificar si el destino es "any"
            if conjunto_acl['destination'] == "any":
                ace_rule["ace-rule"]["dst-any"] = [None]
            else:
                ace_rule["ace-rule"]["dest-mask"] = conjunto_acl['destination']

            lista_acl.append(ace_rule)
            cont += 10


        data= {
        "Cisco-IOS-XE-acl:extended": [
                {
                "name":nat_vpn['id_acl'],
                "access-list-seq-rule": lista_acl
            }

        ]
        }
    data=json.dumps(data)
    print(data)
    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/ip/access-list/",host['username'],host['password'],data)


def configurar_interfaz_nat_resconf(host,lista_hosts,parametros,aplicacion_equipos_herramienta):

    lista_elementos=[]

    for nat_vpn in parametros[host['nombre_equipo']]['nat_vpn']:
        lista_elementos.append(
       {
        "id": nat_vpn['id_acl'],
        "interface": [
            {
            "name": parametros[host['nombre_equipo']]['interfaz_red'].replace(" ",""),
            "overload": [None]
            }
        ]
        }
        )

    data={
        "Cisco-IOS-XE-nat:list": lista_elementos
            }
    data=json.dumps(data)
    print(data)
    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/ip/nat/inside/source",host['username'],host['password'],data)


def creacion_Tunel_vpn_resconf(host,lista_hosts,parametros,aplicacion_equipos_herramienta):

    lista_tuneles=[]


    hostname_equipo_aplicado=host.pop('nombre_equipo')
    if len(lista_hosts)>=2:

        if parametros['hub_vpn']!=hostname_equipo_aplicado:
            clave,ip_vpn=obtener_clave_y_ip("claves.json", str(hostname_equipo_aplicado), parametros["ip_vpn"])
            clave,ip_vpn_hub=obtener_clave_y_ip("claves.json", parametros['hub_vpn'], parametros["ip_vpn"])
            ip_cpe_hub=parametros[parametros['hub_vpn']]['ip_cpe']
            lista_tuneles.append(
                {
                            "name": 0,
                            "ip": {
                            "address": {
                                "primary": {
                                "address": ip_vpn,
                                "mask": "255.255.255.0"
                                }
                            },

                            "Cisco-IOS-XE-nhrp:nhrp-v4": {
                                    "nhrp": {
                                        "nhs": {
                                        "ipv4": [
                                            {
                                            "ipv4": ip_vpn_hub,
                                            "nbma": {
                                                "ipv4": [
                                                {
                                                    "ipv4": ip_cpe_hub,
                                                    "multicast": {
                                                    }
                                                }
                                                ]
                                            }
                                            }
                                        ]
                                        },
                                        "authentication": "DMVPN",
                                        "network-id": 1
                                    }
                                    }
                            }
                                ,
                            "Cisco-IOS-XE-tunnel:tunnel": {
                            "source":  parametros[hostname_equipo_aplicado]['ip_interna'],
                            "destination-config": {
                                "ipv4": ip_cpe_hub
                            },
                            "protection": {
                                "Cisco-IOS-XE-crypto:ipsec": {
                                "profile-option": {
                                    "name": parametros['ipsec_name_profile']
                                }
                                }
                            }
                            }
                        }
            )

        else:

                clave_equipo_local, ip_vpn_local = obtener_clave_y_ip("claves.json", hostname_equipo_aplicado , parametros["ip_vpn"])

                lista_tuneles.append(
                        {
                            "name": 0,
                            "ip": {
                            "address": {
                                "primary": {
                                "address": ip_vpn_local,
                                "mask": "255.255.255.0"
                                }

                            },
                            "redirects": False,
                            "Cisco-IOS-XE-nhrp:nhrp-v4": {
                                "nhrp": {
                                    "authentication": "DMVPN",
                                    "network-id": 1
                                }
                            }
                            },
                            "Cisco-IOS-XE-tunnel:tunnel": {
                            "source":  parametros[hostname_equipo_aplicado]['ip_interna'],
                            "mode":{
                                "gre-config": {
                                    "multipoint": {
                                    }
                                }
                            },

                            "protection": {
                                "Cisco-IOS-XE-crypto:ipsec": {
                                "profile-option": {
                                    "name": parametros['ipsec_name_profile']
                                }
                                }
                            }
                            },
                        }

                )
    else:
            clave,ip_vpn=obtener_clave_y_ip("claves.json", str(hostname_equipo_aplicado), parametros["ip_vpn"])

            ip_cpe_hub=parametros[parametros[lista_hosts[0]]]['ip_cpe']
            lista_tuneles.append(
                {
                            "name": 0,
                            "ip": {
                            "address": {
                                "primary": {
                                "address": ip_vpn,
                                "mask": "255.255.255.252"
                                }
                            },
                            }
                                ,
                            "Cisco-IOS-XE-tunnel:tunnel": {
                            "source":  parametros[hostname_equipo_aplicado]['ip_interna'],
                            "destination-config": {
                                "ipv4": ip_cpe_hub
                            },
                            "protection": {
                                "Cisco-IOS-XE-crypto:ipsec": {
                                "profile-option": {
                                    "name": parametros['ipsec_name_profile']
                                }
                                }
                            }
                            }
                        }
            )


    comando={
        "Tunnel":lista_tuneles
    }
    comando=json.dumps(comando,indent=2)
    print(comando)
    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/interface",host['username'],host['password'],comando)


def ospf_bgp_redistribute(host,lista_hosts,parametros,aplicacion_equipos_herramienta):

    comando={
      "bgp": [{
          "as": parametros[host['nombre_equipo']]['bgp_id'],
      }
      ]
      }

    data=json.dumps(comando)
    print(data)

    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/router/router-ospf/ospf/process-id/1/redistribute/",host['username'],host['password'],data)





def bgp_crear(host,lista_hosts,parametros,aplicacion_equipos_herramienta):

 redes_compartir=[]
 lista_neighboors_lista_=[]

 neighbors=_obtener_neighboor_bgp(host,lista_hosts,parametros)
 for rede_equipo in parametros[host['nombre_equipo']]['redes_compartir']:
        redes_compartir.append(
            {
                "number": rede_equipo['direccion']
            }
        )
 for viceno in neighbors:
     lista_neighboors_lista_.append({
         "id": viceno['id'],
         "activate": [None]
     })


 ospf_creacion={
  "Cisco-IOS-XE-bgp:bgp": [
    {
      "id": parametros[host['nombre_equipo']]['bgp_id'],
      "bgp": {
        "log-neighbor-changes": True
      },
      "neighbor": neighbors,
      "address-family": {
        "no-vrf": {
          "ipv4": [
            {
              "af-name": "unicast",
              "ipv4-unicast": {
                "neighbor": lista_neighboors_lista_,
                "network": {
                  "no-mask": redes_compartir
                }

              }
            }
          ]
        }
      }
    }
  ]
}
 data=json.dumps(ospf_creacion,indent=2)
 print(data)

 aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/router/",host['username'],host['password'],data)


def ikev2_creacion_resconf(host,lista_hosts,parametros,aplicacion_equipos_herramienta):

    peers= _crear_peer_keyring(host,lista_hosts,parametros)


    data = {
        "keyring": [
            {
                "name": parametros['keyring_name'],
                "peer": peers
            }
        ],
        "profile": [
            {
                "name": parametros['profile_ike_v2_name'],
                "authentication": {
                    "local": {
                        "pre-share": {}
                    },
                    "remote": {
                        "pre-share": {}
                    }
                },
                "identity": {
                    "local": {
                        "fqdn": host['nombre_equipo']
                    }
                },
                "keyring": {
                    "local": {
                        "name": parametros['keyring_name']
                    }
                },
                "match": {
                    "identity": {
                        "remote":{
                             "any": [None]
                        }
                    }
                }
            }
        ],
        "proposal": [
            {
                "name": parametros['proporsal_ike_name'],
                "encryption": {
                    parametros['encriptado']: [None]
                },
                "group": {
                    _transform_grupo_dif(parametros['grupo_dif']): [None]
                },
                "prf": {
                    parametros['integridad']: [None]
                }
            }
        ],
        "policy": [
            {
                "name": parametros['policy_name_ike_name'],
                "proposal": [
                    {
                        "proposals": parametros['proporsal_ike_name']
                    }
                ]
            }
        ]
    }
    data=json.dumps(data)
    print(data)

    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/crypto/ikev2",host['username'],host['password'],data)

    return parametros


