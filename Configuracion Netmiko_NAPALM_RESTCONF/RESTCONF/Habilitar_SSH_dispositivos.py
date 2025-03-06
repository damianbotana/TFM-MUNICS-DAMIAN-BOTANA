

def configurar_ssh_restconf(host,lista_hosts,parametros,aplicacion_equipos_herramienta):
    _habilitar_ssh(host,lista_hosts,parametros,aplicacion_equipos_herramienta)
    _habilitar_acceso_por_ssh(host,lista_hosts,parametros,aplicacion_equipos_herramienta)
    return parametros

def _habilitar_ssh(host,lista_hosts,parametros,aplicacion_equipos_herramienta):
    """
        Habilita SSH en un dispositivo Cisco IOS XE utilizando RESTCONF.
        Args:
            host (dict): Diccionario con la información del host, incluyendo 'nombre_equipo', 'direccion', 'username' y 'password'.
            lista_hosts (list): Lista de hosts (no utilizado en esta función).
            parametros (any): Parámetros adicionales que se devolverán sin cambios.
            aplicacion_equipos_herramienta (function): Función para realizar las peticiones HTTP a los equipos.
        Returns:
            any: Devuelve los parámetros recibidos sin cambios.
    """
    data={
        "Cisco-IOS-XE-native:ip":{
        "ssh": {
            "authentication-retries": 2,
            "time-out": 60,
            "version": 2
        },
        "domain": {
            "name": f"{host['nombre_equipo']}.local"
        }
        }

        }

    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/ip",host['username'],host['password'],data)

def _habilitar_acceso_por_ssh(host,lista_hosts,parametros,aplicacion_equipos_herramienta):
    data={
            "Cisco-IOS-XE-native:line": {
                "console": [
                {
                    "first": "0",
                    "stopbits": "1"
                }
                ],
                "vty": [
                {
                    "first": 0,
                    "last": 4,
                    "transport": {
                    "input": {
                        "input": ["ssh"]
                    }
                    }
                }
                ]
            }
            }

    aplicacion_equipos_herramienta(f"https://{host['direccion']}:443/restconf/data/Cisco-IOS-XE-native:native/line/",host['username'],host['password'],data)

