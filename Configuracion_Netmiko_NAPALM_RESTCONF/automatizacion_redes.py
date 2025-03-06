from RESTCONF.Habilitar_SSH_dispositivos import configurar_ssh_restconf
from RESTCONF.Despliegue_VPN import obtener_datos_cpe_nat_restconf,obtener_datos_firewall_nat_vpn_restconf,creacion_nat_puerto, acl_creacion_resconf, configurar_interfaz_nat_resconf, ikev2_creacion_resconf, definir_ipsec_perfil_resconf, creacion_Tunel_vpn_resconf, bgp_crear, ospf_bgp_redistribute
from RESTCONF.Aplicar_politicas_seguridad import configuracion_firewall_zfw_restconf,obtener_acl_firewall_restconf_informacion
from Netmiko_NAPALM.Configuracion_SSH_con_Netmiko_NAPALM import telnet_to_ssh
from Netmiko_NAPALM.Despliegue_VPN_Netmiko_NAPALM import aplicacacion_nat_vpn,creacion_autoridad_certificadora_completo,aplicacion_ca_equipos,vpn_dispositivos_despues_nat
from Netmiko_NAPALM.Aplicacion_politicas_seguridad_Netmiko_NAPALM import aplicar_politicas_excel_DL,aplicar_politicas_excel
from Netmiko_NAPALM.Netmiko.Obtener_informacion_Netmiko import obterner_datos_cpe_nat_vpn_netmiko,obtener_vpn_firewall_netmiko_informacion,obtener_acl_firewall_netmiko_informacion
from Netmiko_NAPALM.NAPALM.Obtener_informacion_NAPALM import obtener_datos_cpe_nat_vpn_napalm,obtener_datos_firewall_nat_napalm
import time
from formato_credenciales_acceso_herramienta import diccionario_conversion
import argparse

inventario_path = "inventario.ini"
ansible_path = "secrets.yml"
ansible_password_file = ".vault_pass.txt"

def _leer_fichero_como_string(ruta_fichero):
    """
    Lee el contenido de un fichero y lo guarda en una cadena de texto.

    Args:
        ruta_fichero (str): La ruta al fichero que se desea leer.

    Returns:
        str: El contenido del fichero como una cadena de texto.
    """
    try:
        with open(ruta_fichero, 'r') as archivo:
            contenido = archivo.read()
        return contenido
    except FileNotFoundError:
        print(f"Error: El fichero {ruta_fichero} no se encontró.")
        return ""
    except IOError:
        print(f"Error: No se pudo leer el fichero {ruta_fichero}.")
        return ""


# AUTOMATIZACION DESPLIEGUE VPN
def automatizacion_vpn_netmiko_certificate(parametros_fw,password_vaul_ansible):
    diccionario_conversion(inventario_path, "netmiko", "isp", creacion_autoridad_certificadora_completo, parametros_fw, False,None,ansible_path,password_vaul_ansible)
    diccionario_conversion(inventario_path, "netmiko", "cpes", aplicacacion_nat_vpn, parametros_fw, False,obterner_datos_cpe_nat_vpn_netmiko,ansible_path,password_vaul_ansible)
    print("***********************")
    diccionario_conversion(inventario_path, "netmiko", "firewalls", aplicacion_ca_equipos, parametros_fw, False,None,ansible_path,password_vaul_ansible)
    diccionario_conversion(inventario_path, "netmiko", "firewalls", vpn_dispositivos_despues_nat, parametros_fw, True,obtener_vpn_firewall_netmiko_informacion,ansible_path,password_vaul_ansible)

def automatizacion_vpn_netmiko_prekey(parametros_fw,password_vaul_ansible):
    diccionario_conversion(inventario_path, "netmiko", "cpes", aplicacacion_nat_vpn, parametros_fw, False,obterner_datos_cpe_nat_vpn_netmiko,ansible_path,password_vaul_ansible)
    print("***********************")
    diccionario_conversion(inventario_path, "netmiko", "firewalls", vpn_dispositivos_despues_nat, parametros_fw, True,obtener_vpn_firewall_netmiko_informacion,ansible_path,password_vaul_ansible)


def automatizacion_vpn_netpalm(parametros_fw,password_vaul_ansible):
    diccionario_conversion(inventario_path, "netpalm", "isp", creacion_autoridad_certificadora_completo, parametros_fw, False,None,ansible_path,password_vaul_ansible)
    diccionario_conversion(inventario_path, "netpalm", "cpes", aplicacacion_nat_vpn, parametros_fw, False,obtener_datos_cpe_nat_vpn_napalm,ansible_path,password_vaul_ansible)
    print("***********************")
    diccionario_conversion(inventario_path, "netpalm", "firewalls", aplicacion_ca_equipos, parametros_fw, False,None,ansible_path,password_vaul_ansible)
    diccionario_conversion(inventario_path, "netpalm", "firewalls", vpn_dispositivos_despues_nat, parametros_fw, True,obtener_datos_firewall_nat_napalm,ansible_path,password_vaul_ansible)


def automatizacion_vpn_netpalm_prekey(parametros_fw,password_vaul_ansible):

    diccionario_conversion(inventario_path, "netpalm", "cpes", aplicacacion_nat_vpn, parametros_fw, False,obtener_datos_cpe_nat_vpn_napalm,ansible_path,password_vaul_ansible)
    print("***********************")

    diccionario_conversion(inventario_path, "netpalm", "firewalls", vpn_dispositivos_despues_nat, parametros_fw, True,obtener_datos_firewall_nat_napalm,ansible_path,password_vaul_ansible)


def automatizacion_vpn_restconf(parametros_fw,password_vaul_ansible):

    parametros_fw=diccionario_conversion(inventario_path, "restconf", "cpes", creacion_nat_puerto, parametros_fw, False,obtener_datos_cpe_nat_restconf,ansible_path,password_vaul_ansible)
    diccionario_conversion(inventario_path, "restconf", "cpes", acl_creacion_resconf, parametros_fw, False,None,ansible_path,password_vaul_ansible)
    diccionario_conversion(inventario_path, "restconf", "cpes", configurar_interfaz_nat_resconf, parametros_fw, False,None,ansible_path,password_vaul_ansible)
    parametros_fw=diccionario_conversion(inventario_path, "restconf", "firewalls", ikev2_creacion_resconf, parametros_fw, True,obtener_datos_firewall_nat_vpn_restconf,ansible_path,password_vaul_ansible)
    diccionario_conversion(inventario_path, "restconf", "firewalls", definir_ipsec_perfil_resconf, parametros_fw, False,None,ansible_path,password_vaul_ansible)
    diccionario_conversion(inventario_path, "restconf", "firewalls", creacion_Tunel_vpn_resconf, parametros_fw, True,None,ansible_path,password_vaul_ansible)
    diccionario_conversion(inventario_path, "restconf", "firewalls", bgp_crear, parametros_fw, True,None,ansible_path,password_vaul_ansible)
    # Se añade un sleep para que le dé tiempo al router el BGP
    time.sleep(4)
    diccionario_conversion(inventario_path, "restconf", "firewalls", ospf_bgp_redistribute, parametros_fw, False,None,ansible_path,password_vaul_ansible)


def automatizacion_acl_restconf(parametros_fw,password_vaul_ansible):

    parametros_fw=diccionario_conversion(inventario_path, "restconf", "FW", configuracion_firewall_zfw_restconf, parametros_fw, False,obtener_acl_firewall_restconf_informacion,ansible_path,password_vaul_ansible)


def automatizacion_acl_netmiko(parametros_fw,password_vaul_ansible):

    diccionario_conversion(inventario_path, "netmiko", "switches", aplicar_politicas_excel_DL, parametros_fw, False,obtener_acl_firewall_netmiko_informacion,ansible_path,password_vaul_ansible)
    diccionario_conversion(inventario_path, "netmiko", "firewalls", aplicar_politicas_excel, parametros_fw, False,obtener_acl_firewall_netmiko_informacion,ansible_path,password_vaul_ansible)

# AUTOMATIZACION CONVERSION TELNET TO SSH ACCESO REMOTO
def automatizacion_conversion_telnet_ssh_netmiko(parametros_fw,password_vaul_ansible):
    dispositivos_aplicar = input("A que dispositivos quieres activar el ssh en vez telnet ").strip().lower()

    #en caso de ser netmiko mediante telnet la herramienta se llama netmiko-telnet

    diccionario_conversion(inventario_path, "netmiko-telnet",dispositivos_aplicar , telnet_to_ssh, parametros_fw, False,None,ansible_path,password_vaul_ansible)

def automatizacion_conversion_telnet_ssh_napalm(parametros_fw,password_vaul_ansible):
    dispositivos_aplicar = input("A que dispositivos quieres activar el ssh en vez telnet ").strip().lower()

    #en caso de ser netmiko mediante telnet la herramienta se llama netmiko-telnet
    diccionario_conversion(inventario_path, "nepalm-telnet",dispositivos_aplicar , telnet_to_ssh, parametros_fw, False,None,ansible_path,password_vaul_ansible)

def automatizacion_conversion_telnet_ssh_restconf(parametros_fw,password_vaul_ansible):
     dispositivos_aplicar = input("A que dispositivos quieres activar el ssh en vez telnet ").strip().lower()

     diccionario_conversion(inventario_path, "restconf",dispositivos_aplicar , configurar_ssh_restconf, parametros_fw, False,None,ansible_path,password_vaul_ansible)
    

def inicio():
    """
    Ejemplo de uso por terminal:
    python automatizacion_redes.py --herramienta netmiko --operacion despliegue_vpn --parametros clave1=valor1,clave2=valor2
    """

    parser = argparse.ArgumentParser(description="Automatización de despliegue y configuración de redes.")
    parser.add_argument('--herramienta', type=str, help="Herramienta a utilizar (netmiko, natpalm, restconf)")
    parser.add_argument('--operacion', type=str, help="Operación a realizar (despliegue_vpn, telnet_to_ssh, acl_securizacion)")
    parser.add_argument('--parametros', type=str, help="Parámetros adicionales en formato clave=valor separados por comas")
    parser.add_argument('--autenticacion', type=str, help="Tipo de autenticación en IKEV2 clave=prekey,certificate")
    args = parser.parse_args()

    parametros_fw = {}
    if args.parametros:
        for param in args.parametros.split(','):
            clave, valor = param.split('=')
            parametros_fw[clave.strip()] = valor.strip()

    password_vaul_ansible = _leer_fichero_como_string(ansible_password_file).strip()

    if args.herramienta:
        herramienta = args.herramienta.strip().lower()
    else:
        herramienta = input("Seleccione la herramienta a utilizar (netmiko, natpalm, restconf): ").strip().lower()

    if herramienta == "netmiko":
        if args.operacion:
            operacion = args.operacion.strip().lower()
        else:
            operacion = input("Seleccione la operación que se quiere realizar (despliegue_vpn, telnet_to_ssh, acl_securizacion): ").strip().lower()

        if operacion == "despliegue_vpn":
            if args.autenticacion:
                autenticacion = args.autenticacion.strip().lower()
            else:
                autenticacion = input("Seleccione la autenticación que quieres realizar (prekey,certificate): ").strip().lower()

            if autenticacion=="certificate":
                parametros_fw['tipo_autenticacion']="rsa-sig"
                automatizacion_vpn_netmiko_certificate(parametros_fw, password_vaul_ansible)
            elif autenticacion=="prekey":
                parametros_fw['tipo_autenticacion']="pre-share"
                automatizacion_vpn_netmiko_prekey(parametros_fw, password_vaul_ansible)

        elif operacion == "telnet_to_ssh":
            automatizacion_conversion_telnet_ssh_netmiko(parametros_fw, password_vaul_ansible)
        elif operacion == "acl_securizacion":
            automatizacion_acl_netmiko(parametros_fw, password_vaul_ansible)
        else:
            print("Operación no reconocida. Por favor, seleccione una operación válida.")

    elif herramienta == "natpalm":
        if args.operacion:
            operacion = args.operacion.strip().lower()
        else:
            operacion = input("Seleccione la operación que se quiere realizar (despliegue_vpn, telnet_to_ssh): ").strip().lower()

        if operacion == "despliegue_vpn":
            if args.autenticacion:
                autenticacion = args.autenticacion.strip().lower()
            else:
                autenticacion = input("Seleccione la autenticación que quieres realizar (prekey,certificate): ").strip().lower()

            if autenticacion=="certificate":
                parametros_fw['tipo_autenticacion']="rsa-sig"
                automatizacion_vpn_netpalm(parametros_fw, password_vaul_ansible)
            elif autenticacion=="prekey":
                parametros_fw['tipo_autenticacion']="pre-share"
                automatizacion_vpn_netpalm_prekey(parametros_fw, password_vaul_ansible)
        elif operacion == "telnet_to_ssh":
            automatizacion_conversion_telnet_ssh_napalm(parametros_fw, password_vaul_ansible)
        else:
            print("Operación no reconocida. Por favor, seleccione una operación válida.")

    elif herramienta == "restconf":
        if args.operacion:
            operacion = args.operacion.strip().lower()
        else:
            operacion = input("Seleccione la operación que se quiere realizar (despliegue_vpn, telnet_to_ssh): ").strip().lower()

        if operacion == "despliegue_vpn":
            automatizacion_vpn_restconf(parametros_fw, password_vaul_ansible)
        elif operacion == "telnet_to_ssh":
            automatizacion_conversion_telnet_ssh_restconf(parametros_fw, password_vaul_ansible)

        elif operacion == "acl_securizacion":
            automatizacion_acl_restconf(parametros_fw, password_vaul_ansible)
        else:
            print("Operación no reconocida. Por favor, seleccione una operación válida.")

    else:
        print("Herramienta no reconocida. Por favor, seleccione una herramienta válida.")


inicio()


