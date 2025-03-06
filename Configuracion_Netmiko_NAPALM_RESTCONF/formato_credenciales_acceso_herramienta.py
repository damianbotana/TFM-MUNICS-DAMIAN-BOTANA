from leer_inventario import get_inventory_details
from RESTCONF.Configuraccion_acceso_dispositivos_RESTCONF import operacciones_restconf
from Netmiko_NAPALM.Netmiko.configuracion_acceso_dispositivos_netmiko import operacciones_netmiko
from Netmiko_NAPALM.NAPALM.configuracion_acceso_dispositivo_NAPALM import operacciones_nepalm

def _obtener_variables_todos_equipos(host_vars):

    return {
        "subname": host_vars['subname'],
        "password_ca": str(host_vars['password_ca']),
        "ip_ca": host_vars['ip_ca'],
        "red_administracion": host_vars['red_administracion'],

    }

# Fichero encargado de transformar el fichero ini en un formato que entiende la herramienta de automatización
def diccionario_conversion(inventory_path, tool, host_select, operacion_automaticacion, parametros,conocimiento_otros_host,obtencion_datos_dispositivos,vault_file, vault_password):
    all_vars, hosts = get_inventory_details(inventory_path, host_select,vault_file, vault_password)
    #se guardan en el diccionario las variables de todos los usuarios
    parametros.update(_obtener_variables_todos_equipos(all_vars))
    # Crear host_list utilizando una lista por comprensión
    host_list = [
        {
            "nombre": host['inventory_hostname'],
            "direccion": host.get('ansible_host', 'IP no definida')
        }
        for host in hosts
    ]


    host_list_aux=[]

    diccionario_final={}

    operaccion=None
    if obtencion_datos_dispositivos != None:
        parametros['mismo_formato_red']=False

    # Iterar sobre hosts y realizar la operación automatizada
    for host in hosts:

        credenciales_dispositivo = {
            "nombre_equipo": host['inventory_hostname'],
            "username": all_vars.get('ansible_user'),
            "password": all_vars.get('ansible_password')
        }

        if tool in ['netmiko', 'netmiko-telnet']:
            credenciales_dispositivo.update({
            "device_type": "cisco_ios" if tool == 'netmiko' else "cisco_ios_telnet",
            "host": host.get('ansible_host', 'IP no definida'),
            "secret": all_vars.get('ansible_become_password')  # Enable password
            })
            operaccion = operacciones_netmiko


        elif tool in ['netpalm','nepalm-telnet']:
            credenciales_dispositivo.update({
                "hostname": host.get('ansible_host', 'IP no definida'),
                "optional_args": {
                                "secret": all_vars.get('ansible_become_password'),
                                "transport": "ssh" if tool == 'netpalm' else "telnet"
                                  }
            })
            operaccion=operacciones_nepalm
        elif tool == "restconf":
            credenciales_dispositivo.update({
                "direccion": host.get('ansible_host', 'IP no definida'),
            })
            operaccion=operacciones_restconf

        # caso de no necesitarse el conocimiento de los datos de los otros host del grupo se eleminar
        if  conocimiento_otros_host:

            # Crear una lista auxiliar sin el host actual
            host_list_aux = [h for h in host_list if h["nombre"] != host['inventory_hostname']]

        #en caso que se pase una funcion para obtener datos de los dispositivos se ejecuta y se le pasa posteriormente dicha informacion al dispositivo en el diccionario
        if obtencion_datos_dispositivos != None:
            parametros=obtencion_datos_dispositivos(credenciales_dispositivo,parametros,host,host_select)



        diccionario= operacion_automaticacion(credenciales_dispositivo, host_list_aux, parametros,operaccion)
        if diccionario != None:
            diccionario_final.update(diccionario)

    return diccionario_final






