import json
from Configuraccion_acceso_dispositivos_RESTCONF import obtener_informacion_restconf
import requests
from requests.auth import HTTPBasicAuth
import pandas as pd
file_path = '..politica_seguridad.xlsx'

#----------------------------------------------------------------Obtener información----------------------------------
def obtener_acl_firewall_restconf_informacion(host, parametros, host_vars, grupo_aplicado):
    """
    Función que obtiene las zonas de seguridad de un firewall Cisco ASA utilizando RESTCONF.
    Args:
        cisco_01 (dict): Diccionario con la información de conexión del dispositivo.
    Returns:
        list: Lista de zonas de seguridad del firewall.
    """
    interfaces={"Tunnel0":set()}
    interfaz_internet=""
    vecino_ip=""
    data = obtener_informacion_restconf(
        f"https://{host['direccion']}:443/restconf/data/ietf-routing:routing-state/routing-instance=default/ribs/rib=ipv4-default/routes/route/",
        host['username'], host['password']

    )

    for elemento in data['ietf-routing:route']:
        for nombre, ip in host_vars['vlan_ips'].items():

            if nombre != "Internet" and nombre != "CORE" and elemento['destination-prefix'] != "0.0.0.0/0" and not nombre.endswith('_mask') :

                mascara=IPv4Address._prefix_from_ip_int(int(IPv4Address(host_vars['vlan_ips'][f'{nombre}_mask']))^(2**32-1))
                red=ipaddress.ip_network(f"{elemento['destination-prefix']}")
                red2=ipaddress.ip_network(f"{ip}/{mascara}")

                if red.subnet_of(red2) or red2.subnet_of(red):
                    interfaz = elemento['next-hop']['outgoing-interface']
                    if ipaddress.ip_address(elemento['next-hop']['next-hop-address']) in ipaddress.ip_network(host_vars['red_vpn']):
                        interfaces["Tunnel0"].add(nombre)
                        continue
                    if interfaz not in interfaces:
                        interfaces[interfaz] = set()
                    interfaces[interfaz].add(nombre)


            elif elemento['destination-prefix'] == "0.0.0.0/0":
                interfaz_internet = elemento['next-hop']['outgoing-interface']

                if interfaz_internet not in interfaces:
                    interfaces[interfaz_internet] = set()
                interfaces[interfaz_internet].add("Internet")
                vecino_ip=elemento['next-hop']['next-hop-address']
                #for vecino_ospf in vecino_data['Cisco-IOS-XE-ospf-oper:ospf-instance'][0]['ospf-area'][0]['ospf-interface']:
                 #   if ipaddress.ip_address(vecino_ospf['ospf-neighbor'][0]['address']) in ipaddress.ip_network(red, strict=False):
                   # print(vecino_ospf)

    parametros.update({
        'vecino_ospf': vecino_ip,
        #cambiar esto
        'ip_propia_ospf': "10.0.0.5",
        'interfaces': interfaces,
        'vlan_ips': host_vars['vlan_ips'],
    })
    return parametros

#------------------------------------------------------------Aplicacion configuracion----------------------------------------------------------
def _crear_acl_gestion(ip_propia,vecino):
    diccionario_acl={}
    diccionario_acl['FIREWALL_CONTESTACION']=[
            {
                "action": "permit",
                "protocol": "udp",
                "origen": ip_propia,
                "destino": "any",
                "puerto_destino":"isakmp"
            },
            {
                "action": "permit",
                "protocol": "udp",
                "origen": ip_propia,
                "destino": "any",
                "puerto_destino":"non500-isakmp"
            },
            {
                "action": "permit",
                "protocol": "esp",
                "origen": ip_propia,
                "destino": "any",

            },
            {
                "action": "deny",
                "protocol": "ip",
                "origen": "any",
                "destino": "any",

            }


    ]
    diccionario_acl["INTERNET_OSPF"]=[
            {
                "action": "permit",
                "protocol": "ospf",
                "origen": vecino,
                "destino": ip_propia,
            },
             {
                "action": "permit",
                "protocol": "ospf",
                "origen": vecino,
                "destino": "224.0.0.5",
            },
             {
                "action": "permit",
                "protocol": "ospf",
                "origen": vecino,
                "destino": "224.0.0.6",
            },
            {
                "action": "permit",
                "protocol": "esp",
                "origen":"any" ,
                "destino": ip_propia,
            },
            {
                "action": "permit",
                "protocol": "udp",
                "origen":"any" ,
                "destino": ip_propia,
                "puerto_destino":"isakmp"
            },
            {
                "action": "permit",
                "protocol": "udp",
                "origen":"any" ,
                "destino": ip_propia,
                "puerto_destino":"non500-isakmp"
            },
            {
                "action": "deny",
                "protocol": "ip",
                "origen": "any",
                "destino": "any",

            }
    ]
    return diccionario_acl

def _crear_policy(lista_pass,lista_inspecct):
    diccionario_policy={}
    for nombre_pass in lista_pass:
        diccionario_policy[nombre_pass+"CLASS_MAP"]={
            "action": "pass",
            "nombre_acl": nombre_pass,
            "nombre_policy_map": nombre_pass+"POLICY"
        }
    for nombre_inspect in lista_inspecct:
        diccionario_policy[nombre_inspect+"CLASS_MAP"]={
            "action": "inspect",
            "nombre_acl": nombre_inspect,
            "nombre_policy_map": nombre_inspect+"POLICY"
        }
    return diccionario_policy

def _crear_zonas_interfaz(interfaces):
    diccionario_zonas={}
    for interfaz,redes in interfaces.items():
         match = re.match(r'([A-Za-z]+)(\d.*)', interfaz)

         if match and redes!=[]:
            diccionario_zonas.setdefault(match.group(1), {})[match.group(2)] = {"zona": ','.join(redes)}
    return diccionario_zonas


def _crear_zonas(lista_origenes,lista_destino,nombres_policy_map):
    lista=[]
    for origen,destino,policy_map in zip(lista_origenes,lista_destino,nombres_policy_map):
        diccionario={}
        diccionario['origen']=origen
        diccionario['destino']=destino
        diccionario['nombre_policy_map']=policy_map+"POLICY"
        lista.append(diccionario)

    return lista

def _generar_acl(origen,destino,contenido_permitido,parametros):

    lista_acl=[]
    origen_acl=""
    mascara_acl=""
    destino_acl=""
    destino_mask_acl=""

    #convetir el contenido permitido en una lista sabiendo que esta separado por comas
    contenido_permitido=contenido_permitido.split(",")
    #en caso de ser internet el origen se deniega primero el trafico propio de la red de la organización

    if origen=="Internet":
       lista_acl.append({
                "action": "deny",
                "protocol": "ip",
                "origen": parametros['vlan_ips']['CORE'],
                "mask":parametros['vlan_ips']["CORE_mask"],
                "destino": parametros['vlan_ips'][destino],
                "mask_destino":parametros['vlan_ips'][destino+"_mask"]

            })
       origen_acl="any"
       destino_acl=parametros['vlan_ips'][destino]
       destino_mask_acl=parametros['vlan_ips'][destino+"_mask"]


    elif destino=="Internet":
         lista_acl.append({
                "action": "deny",
                "protocol": "ip",
                "origen": parametros['vlan_ips'][origen],
                "mask":parametros['vlan_ips'][origen+"_mask"],
                "destino": parametros['vlan_ips']['CORE'],
                "mask_destino":parametros['vlan_ips']["CORE_mask"]
            })
         destino_acl="any"
         origen_acl=parametros['vlan_ips'][origen]
         mascara_acl=parametros['vlan_ips'][origen+"_mask"]
    else:
        origen_acl=parametros['vlan_ips'][origen]
        mascara_acl=parametros['vlan_ips'][origen+"_mask"]
        destino_acl=parametros['vlan_ips'][destino]
        destino_mask_acl=parametros['vlan_ips'][destino+"_mask"]
        origen_acl=parametros['vlan_ips'][origen]
        destino_acl=parametros['vlan_ips'][destino]

    for contenido in contenido_permitido:
        acl={
                "action": "permit",
                "origen": origen_acl,
                "destino": destino_acl,
            }
        if mascara_acl!="":
            acl['mask']=mascara_acl
        if destino_mask_acl!="" and contenido.strip()!="DHCP":
            acl['mask_destino']=destino_mask_acl

        if contenido.strip()=="HTTP":
           acl['protocol']="tcp"
           acl['puerto_destino']="www"
           lista_acl.append(acl)

        elif contenido.strip()=="HTTPS":
           acl['protocol']="tcp"
           acl['puerto_destino']=443
           lista_acl.append(acl)

        elif contenido.strip()=="DNS":
            acl['protocol']="udp"
            acl_copy = acl.copy()
            acl_copy['puerto_destino'] = "domain"
            lista_acl.append(acl_copy)
            acl_copy = acl.copy()
            acl_copy['protocol'] = "tcp"
            lista_acl.append(acl_copy)



        elif contenido.strip()=="ICMP (ping)":
            acl['protocol']="icmp"
            acl_copy = acl.copy()
            acl_copy['dst-eq-port2']='echo'
            lista_acl.append(acl_copy)

            acl['tipo_mensaje']="echo-reply"
            lista_acl.append(acl)

        elif contenido.strip()=="DHCP":
             acl['protocol']="udp"
             acl["destino"]="any"

             acl_copy = acl.copy()
             acl_copy['puerto_destino']="bootps"
             lista_acl.append( acl_copy)
             acl["puerto_destino"]="bootpc"
             lista_acl.append(acl)


    return lista_acl
def _crear_politicas_excel(interfaces_redes,parametros):
    # Leer el archivo Excel sin encabezado
    df = pd.read_excel(file_path,index_col='O/D')

    diccionario_acl={}
    lista_nombre_elementos=[]
    lista_origenes=[]
    lista_destinos=[]
    lista_gestion=[]


    for _,lista_origenes_trafico in interfaces_redes.items():
        for _,lista_destinos_trafico in interfaces_redes.items():

            if lista_origenes_trafico!=[] and lista_destinos_trafico!=[] and lista_origenes_trafico!=lista_destinos_trafico:

               origen_strings_lsita=','.join(lista_origenes_trafico)
               destino_strings_lsita=','.join(lista_destinos_trafico)
               diccionario_acl[origen_strings_lsita+"TO"+destino_strings_lsita]=[]

               #se obtiene el trafico permitido por cada elemento grupal de las acl
               for origen in lista_origenes_trafico:
                   for destino in lista_destinos_trafico:
                          #se supone que la red de administracción tiene que estar denegado el tráfico de otras redes por lo tanto se denegaría
                          if origen != destino and origen != 'ADM' and destino != 'ADM':
                            if df.at[origen, destino] != 'NO':
                                 diccionario_acl[origen_strings_lsita+"TO"+destino_strings_lsita].extend(_generar_acl(origen,destino,df.at[origen, destino],parametros))
                          elif origen == 'ADM' and destino == 'ADM':
                                diccionario_acl['ADM']=[
                                    {
                                "action": "permit",
                                "protocol": "ip",
                                "origen": parametros['vlan_ips'][origen],
                                "mask":parametros['vlan_ips'][origen+"_mask"],
                                "destino": parametros['vlan_ips'][destino],
                                "mask_destino":parametros['vlan_ips'][destino+"_mask"],
                                },
                                {
                                    "action": "deny",
                                    "protocol": "ip",
                                    "origen": "any",
                                    "destino": "any",

                                }
                                ]


               if  diccionario_acl[origen_strings_lsita+"TO"+destino_strings_lsita]==[]:
                   continue
               diccionario_acl[origen_strings_lsita+"TO"+destino_strings_lsita].extend([
                   {
                                    "action": "deny",
                                    "protocol": "ip",
                                    "origen": "any",
                                    "destino": "any",

                                }
               ])
               lista_origenes.append(origen_strings_lsita)
               lista_destinos.append(destino_strings_lsita)
               lista_gestion.append(origen_strings_lsita+"TO"+destino_strings_lsita)

    diccionario_acl

    return diccionario_acl,lista_origenes,lista_destinos,lista_gestion


def configuracion_firewall_zfw_restconf(host,lista_hosts,parametros,aplicacion_equipos_herramienta):


    diccionario_acl=_crear_acl_gestion(parametros['ip_propia_ospf'],parametros['vecino_ospf'])
    lista_zonas=[]
    lista_origenes=['Internet','self']
    lista_destino=['self','Internet']
    lista_gestion=["INTERNET_OSPF","FIREWALL_CONTESTACION",]

    #crear listado de las zonas del diccionario
    for interfaz,redes in parametros['interfaces'].items():
        zona=""
        if redes!=[] and redes!=set():
            zona+=','.join(redes)
            lista_zonas.append(zona)
    print("lista_zonas",lista_zonas)

    crear_zonas(host,lista_zonas,aplicacion_equipos_herramienta)

    politicas_excel,origenes,destinos,gestiones=_crear_politicas_excel(parametros['interfaces'],parametros)
    diccionario_acl.update(politicas_excel)
    lista_origenes.extend(origenes)
    lista_destino.extend(destinos)

    acl_zfw_creacion(host,diccionario_acl,aplicacion_equipos_herramienta)


    diccionario_policy=_crear_policy(lista_gestion,gestiones)
    crear_policy_restconf(host,diccionario_policy,aplicacion_equipos_herramienta)

    interfaces_acl=_crear_zonas_interfaz(parametros['interfaces'])

    crear_interfaz_zonas(host,interfaces_acl,aplicacion_equipos_herramienta)
    print("Origenes",lista_origenes)
    print("Destino",lista_destino)
    lista_gestion.extend(gestiones)
    print("Gestion",lista_gestion)

    zonas_pair=_crear_zonas(lista_origenes,lista_destino,lista_gestion)
    print(zonas_pair)
    crear_zonas_pair(host,zonas_pair,aplicacion_equipos_herramienta)




def acl_zfw_creacion(host,lista_acl,aplicacion_equipos_herramienta):
    #lista_acl es un diccionario con el nombre y como clave  la lista de las acl
    lista_elementos=[]


    for nombre,acls in lista_acl.items():
        lista_ace=[]
        cont=10
        for acl in acls:

            ace={
                "action": acl['action'],
                "protocol": acl['protocol'],
            }
            #se compruba si existe una mascara en caso contrario significará que es un host
            if 'mask' not in acl:
                if acl['origen']!="any":
                    ace['host']=acl['origen']
                else:
                    ace['any']=[None]

            else:
                ace['ipv4-address']=acl['origen']
                ace['mask']=acl['mask']
            if 'mask_destino' not in acl:
                if acl['destino']!="any":
                    ace['dst-host']=acl['destino']
                else:
                    ace['dst-any']=[None]
            else:
                ace['dest-ipv4-address']=acl['destino']
                ace['dest-mask']=acl['mask_destino']
            if 'puerto_orige' in acl:
                ace['eq']=acl['puerto_orige']
            if 'puerto_destino' in acl:
                ace['dst-eq']=acl['puerto_destino']
            if 'tipo_mensaje' in acl:
                ace['named-msg-type']=acl['tipo_mensaje']
            if 'dst-eq-port2' in acl and acl['dst-eq-port2'] != "":
                ace['dst-eq-port2']=acl['dst-eq-port2']
            print(ace)
            lista_ace.append({
                        "sequence": str(cont),
                        "ace-rule": ace
            })
            cont+=10

        lista_elementos.append(
                {
                    "name": nombre,
                    "access-list-seq-rule": lista_ace
                }
            )
    data= {
        "Cisco-IOS-XE-acl:extended": lista_elementos
        }
    data=json.dumps(data,indent=2)
    print(data)
    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/ip/access-list/",host['username'],host['password'],data)

def crear_policy_restconf(host,diccionario_policy,aplicacion_equipos_herramienta):
    lista_policy=[]
    lista_policy_map=[]
    for nombre,policy in diccionario_policy.items():
        lista_policy.append(
            {
                "name": nombre,
                "type": "inspect",
                "prematch": "match-any",
                "match": {
                    "access-group": {
                    "name": [policy['nombre_acl']]
                    }
                }
            }
        )
        lista_policy_map.append(
            {
          "name": policy['nombre_policy_map'],
          "type": "inspect",
          "class": [
            {
              "name": nombre,
              "type": "inspect",
              "policy": {
                "action": policy['action']
              }
            },
            {
              "name": "class-default",
              "policy": {
                "action": "drop"
              }
            }
          ]
        }

        )

    data={
        "Cisco-IOS-XE-policy:class-map": lista_policy,
         "Cisco-IOS-XE-policy:policy-map": lista_policy_map

    }
    data=json.dumps(data)
    print(data)
    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/policy/",host['username'],host['password'],data)

def crear_interfaz_zonas(host,diccionario_interfaces,aplicacion_equipos_herramienta):
#diccionario_interfaces= {"Gigabit":{identificador:{zona:nombre_zona}}}
    data={}
    for nombre_grupo,diccionario_elementos in diccionario_interfaces.items():
        lista_elementos=[]
        print(diccionario_elementos)
        for identificador_interfaz,elementos_interfaz in diccionario_elementos.items():
            if elementos_interfaz['zona'] !="":
                print(elementos_interfaz['zona'])

                lista_elementos.append(
                    {
                        "name": identificador_interfaz,
                        "Cisco-IOS-XE-zone:zone-member": {
                            "security": elementos_interfaz['zona']
                        }
                    }
                )
        data[nombre_grupo]=lista_elementos
    restconf_estructura={
        "Cisco-IOS-XE-native:interface": data
    }
    data=restconf_estructura
    print(data)
    print(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/interface/")

    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/interface",host['username'],host['password'],data)

def crear_zonas(host,lista_zonas,aplicacion_equipos_herramienta):
    zonas=[]
    for zona in lista_zonas:
        zonas.append(
            {
                "id": zona
            }
        )

    data={
        "Cisco-IOS-XE-zone:security": zonas
    }
    data=json.dumps(data)
    print(data)
    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/zone",host['username'],host['password'],data)

def crear_zonas_pair(host,lista_zonas,aplicacion_equipos_herramienta):
    zonas=[]
    for zona in lista_zonas:
        zonas.append(
            {
                 "id": str(zona['origen'])+"_TO_"+str(zona['destino']),
                "source": zona['origen'],
                "destination": zona['destino'],
                "service-policy": {
                    "type": {
                    "inspect": zona['nombre_policy_map']
                    }
                }
            }
        )

    data={
        "Cisco-IOS-XE-zone:security": zonas
    }
    data=json.dumps(data,indent=2)
    print(data)
    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/zone-pair",host['username'],host['password'],data)





