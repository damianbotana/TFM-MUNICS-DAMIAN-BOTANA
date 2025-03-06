from operacciones_cisco_parametrizadas import asignar_politicas_zonas,crear_policy_zfw,crear_clas_map,asociar_zona_interfaz,creacion_zonas_seguridad,aplicar_acl_cbac,sumar_a_ip,crear_tunel_hub,crear_tunel_spoke,crear_autoridad_certificadora,obtener_clave_y_ip,crear_red_ospf_bgp,generar_crear_osfp_id,definicion_ca_que_se_utiliza,crear_red_bgp,traduccion_direcciones_nat,traduccion_nat_estatica,crear_perfil_ikev2,definicion_crypto_map,creacion_propuesta_ikev2,crear_perfil_ipsec,crear_politica_ikev2,crear_key_ring
import pandas as pd

file_path = '../politica_seguridad.xlsx'

def aplicar_politicas_excel(host, lista_hosts,parametros,aplicacion_equipos_herramienta):
    hostname_equipo_aplicado=host.pop('nombre_equipo')
    #añadir más condiciones en caso de las vlans


    #se crean las zonas de seguridad
    comandos=_crear_zonas(parametros['interfaces_redes'])
    #se configura el trafico necesariopara el funcionamiento del equipo
    comandos+=_trafico_gestion_acl_firewall_permitir(parametros['ip_propia_ospf'],parametros['vecino_ospf'])
    comandos+=obtener_politicas_excel(parametros,parametros['interfaces_redes'])

    #comandos=obtener_politicas_excel(parametros,origenes_trafico_interfaz)
    aplicacion_equipos_herramienta(host,comandos,[],[],[])

def aplicar_politicas_excel_DL(host, lista_hosts,parametros,aplicacion_equipos_herramienta):
    hostname_equipo_aplicado=host.pop('nombre_equipo')
    #añadir más condiciones en caso de las vlans

    df = pd.read_excel(file_path,index_col='O/D')
    comandos=""
    #se crean las zonas de seguridad

    for interfaces,lista_origenes_trafico in parametros['interfaces_redes'].items():
        if interfaces=="Tunnel0":
            continue
        acl=""
        for _,lista_destinos_trafico in parametros['interfaces_redes'].items():

            if lista_origenes_trafico!=[] and lista_destinos_trafico!=[] and lista_origenes_trafico!=lista_destinos_trafico:
               origen_strings_lsita=','.join(lista_origenes_trafico)
               #se obtiene el trafico permitido por cada elemento grupal de las acl
               for origen in lista_origenes_trafico:
                   for destino in lista_destinos_trafico:
                          #se supone que la red de administracción tiene que estar denegado el tráfico de otras redes por lo tanto se denegaría
                          if origen != destino and origen != 'ADM' and destino != 'ADM':
                            if df.at[origen, destino] != 'NO':
                                 acl+=_generar_acl(origen,destino,df.at[origen, destino],parametros)



                                #acl+=f"deny ip {parametros['vlan_ips'][origen]} {origen_mask} {destino_mask} \n"

            elif  'ADM' in lista_origenes_trafico and 'ADM' in lista_destinos_trafico:

                acl+=f"permit ip {parametros['vlan_ips']['ADM']} {parametros['vlan_ips']['ADM_mask']} {parametros['vlan_ips']['ADM']} {parametros['vlan_ips']['ADM_mask']}\n"

        if lista_origenes_trafico!=[] and lista_destinos_trafico!=[] and lista_origenes_trafico!=lista_destinos_trafico:
            origen_strings_lsita=','.join(lista_origenes_trafico)
            comandos+=f"ip access-list extended ACL_{origen_strings_lsita}\n"
            if interfaces==parametros['interfaz_internet']:

                continue
            comandos+=acl
            comandos+="deny ip any any\n"
            comandos+=f"interface {interfaces}\n"
            comandos+=f"ip access-group ACL_{origen_strings_lsita} in\n"


    #comandos=obtener_politicas_excel(parametros,origenes_trafico_interfaz)
    aplicacion_equipos_herramienta(host,comandos,[],[],[])

def _generar_acl(origen,destino,contenido_permitido,parametros):
    comando=""
    #convetir el contenido permitido en una lista sabiendo que esta separado por comas
    contenido_permitido=contenido_permitido.split(",")
    #en caso de ser internet el origen se deniega primero el trafico propio de la red de la organización
    red_core=str(parametros['vlan_ips']['CORE'])+" "+str(parametros['vlan_ips']["CORE_mask"])
    if origen=="Internet":
        destino_acl=str(parametros['vlan_ips'][destino])+" "+str(parametros['vlan_ips'][destino+"_mask"])
        comando+=f"deny ip {red_core} {destino_acl} \n"
        origen_acl="any"

    elif destino=="Internet":
        origen_acl=str(parametros['vlan_ips'][origen])+" "+str(parametros['vlan_ips'][origen+"_mask"])
        comando+=f"deny ip {origen_acl} {red_core}   \n"
        destino_acl="any"
    else:
        origen_acl=str(parametros['vlan_ips'][origen])+" "+str(parametros['vlan_ips'][origen+"_mask"])
        destino_acl=str(parametros['vlan_ips'][destino])+" "+str(parametros['vlan_ips'][destino+"_mask"])

    for contenido in contenido_permitido:
        if contenido.strip()=="HTTP":
            comando+=f"permit tcp {origen_acl} {destino_acl} eq 80\n"
        elif contenido.strip()=="HTTPS":
            comando+=f"permit tcp {origen_acl} {destino_acl} eq 443\n"
        elif contenido.strip()=="DNS":
            comando+=f"permit udp {origen_acl} {destino_acl} eq 53\n"
            comando+=f"permit tcp {origen_acl} {destino_acl} eq 53\n"
        elif contenido.strip()=="ICMP (ping)":
            comando+=f"permit icmp {origen_acl} {destino_acl} echo\n"
            comando+=f"permit icmp {origen_acl} {destino_acl} echo-reply\n"
        elif contenido.strip()=="DHCP":
            comando+=f"permit udp any any eq 67\n"
            comando+=f"permit udp any any eq 68\n"


    return comando




def obtener_politicas_excel(parametros,interfaces_redes):
    """
    origenes_trafico_interfaz: es un diccionario que contine los campos
        - origen_trafico: represente el nombre del destino del trafico
        - interfaz: representa la interfaz por la que se envia el trafico

    """

    # Leer el archivo Excel sin encabezado
    df = pd.read_excel(file_path,index_col='O/D')


    comandos=""

    for _,lista_origenes_trafico in interfaces_redes.items():
        for _,lista_destinos_trafico in interfaces_redes.items():

            if lista_origenes_trafico!=[] and lista_destinos_trafico!=[] and lista_origenes_trafico!=lista_destinos_trafico:

               origen_strings_lsita=','.join(lista_origenes_trafico)
               destino_strings_lsita=','.join(lista_destinos_trafico)

               acl=""
               #se obtiene el trafico permitido por cada elemento grupal de las acl
               for origen in lista_origenes_trafico:
                   for destino in lista_destinos_trafico:
                          #se supone que la red de administracción tiene que estar denegado el tráfico de otras redes por lo tanto se denegaría
                          if origen != destino and origen != 'ADM' and destino != 'ADM':
                            if df.at[origen, destino] != 'NO':
                                 acl+=_generar_acl(origen,destino,df.at[origen, destino],parametros)
                          elif origen == 'ADM' and destino == 'ADM':
                                acl+=f"permit ip {parametros['vlan_ips'][origen]} {parametros['vlan_ips'][destino]} \n"

               if acl=="":
                   continue
               comandos+=f"ip access-list extended ACL_{origen_strings_lsita}_{destino_strings_lsita}\n"
               comandos+=acl
               comandos+="deny ip any any\n"
               comandos+=crear_clas_map(f"Trafico_de_{origen_strings_lsita}_{destino_strings_lsita}",f"ACL_{origen_strings_lsita}_{destino_strings_lsita}")
               comandos+=crear_policy_zfw(f"Politica_{origen_strings_lsita}_{destino_strings_lsita}",f"Trafico_de_{origen_strings_lsita}_{destino_strings_lsita}","inspect")
               comandos+=asignar_politicas_zonas(f"{origen_strings_lsita}_TO_{destino_strings_lsita}",origen_strings_lsita,destino_strings_lsita,f"Politica_{origen_strings_lsita}_{destino_strings_lsita}")




    return comandos

def _crear_zonas(interfaces_redes):
    "Funcion que asigna una zona a cada interfaz"

    comandos=""
    for interfaz,redes in interfaces_redes.items():

        if redes!=[]:

            comandos+=creacion_zonas_seguridad(','.join(redes),f"zona correspondiente a la red {','.join(redes)}")
            comandos+=asociar_zona_interfaz(interfaz,','.join(redes))

    return comandos




def _trafico_gestion_acl_firewall_permitir(ip_propia,vecino):
    acl_ospf=f"""
    ip access-list extended ACL_INTERNET_OSPF
    permit ospf host {vecino}  host {ip_propia}
    permit ospf host {vecino} host 224.0.0.5
    permit ospf host {vecino} host 224.0.0.6
    permit esp   any host {ip_propia}
    permit  udp   any host {ip_propia}  eq 500
    permit  udp   any host {ip_propia}  eq 4500

    deny ip any any
     ip access-list extended ACL_FIREWALL_CONTESTACION
     permit udp host {ip_propia} any eq 500
     permit udp host {ip_propia} any eq 4500
     permit esp   host {ip_propia} any
     deny ip any any

    """

    acl_ospf+=crear_clas_map("Trafico_OSPF_Internet_interfaz","ACL_INTERNET_OSPF")
    acl_ospf+=crear_clas_map("Trafico_OSPF_propia_Firewall","ACL_FIREWALL_CONTESTACION")
    acl_ospf+=crear_policy_zfw("Trafico_OSPF_Internet_interfaz_Politica","Trafico_OSPF_Internet_interfaz","inspect")
    acl_ospf+=crear_policy_zfw("Trafico_OSPF_Firewall","Trafico_OSPF_propia_Firewall","pass")
    acl_ospf+=asignar_politicas_zonas("INTERNET_TO_Self","Internet","self","Trafico_OSPF_Internet_interfaz_Politica")
    acl_ospf+=asignar_politicas_zonas("Self_TO_Internet","self","Internet","Trafico_OSPF_Firewall")
    return acl_ospf

