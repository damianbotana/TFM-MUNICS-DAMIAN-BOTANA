from napalm import get_network_driver


def obtener_linea_posterior(texto, marcador):
    lineas = texto.split('\n')
    for i, linea in enumerate(lineas):
        if marcador in linea:
            if i + 1 < len(lineas):
                return lineas[i + 1]
    return None

def obtener_informacion_napalm(host,lista_operacciones,lista_palabras_guardar):
    """
    Conecta a un dispositivo de red utilizando NAPALM y obtiene información específica basada en las operaciones solicitadas.
    Args:
        host (dict): Diccionario con la información de conexión del dispositivo (por ejemplo, dirección IP, usuario, contraseña).
        lista_operaciones (list): Lista de operaciones a realizar en el dispositivo (por ejemplo, "get_facts", "get_interfaces").
        lista_palabras_guardar (list): Lista de palabras clave para guardar los resultados de las operaciones correspondientes.
    Returns:
        dict: Diccionario con los resultados de las operaciones solicitadas, donde las claves son las palabras de `lista_palabras_guardar` y los valores son los resultados de las operaciones.
    """

    driver = get_network_driver('ios')

    switch_01_conn = driver(**host)
    switch_01_conn.open()
    diccionario={}
    for operaccion,palabra_guardar in zip(lista_operacciones,lista_palabras_guardar):
        if operaccion == "get_facts":
            diccionario[palabra_guardar]=switch_01_conn.get_facts()
        elif operaccion == "get_interfaces":
            diccionario[palabra_guardar]=switch_01_conn.get_interfaces()
        elif operaccion == "get_interfaces_ip":
            diccionario[palabra_guardar]=switch_01_conn.get_interfaces_ip()
        elif operaccion == "get_interfaces_counters":
            diccionario[palabra_guardar]=switch_01_conn.get_interfaces_counters()
        elif operaccion == "get_environment":
            diccionario[palabra_guardar]=switch_01_conn.get_environment()
        elif operaccion == "get_arp_table":
            diccionario[palabra_guardar]=switch_01_conn.get_arp_table()
        elif operaccion == "get_probes_config":
            diccionario[palabra_guardar]=switch_01_conn.get_probes_config()
        elif operaccion == "get_snmp_information":
            diccionario[palabra_guardar]=switch_01_conn.get_snmp_information()
        elif operaccion == "get_network_instances":
            diccionario[palabra_guardar]=switch_01_conn.get_network_instances()
        elif operaccion == "ip_interfaz_internet":
            diccionario['ip_puerta_enlace']=switch_01_conn.get_route_to("0.0.0.0/0")['0.0.0.0/0'][0]['next_hop']
            diccionario['interfaz_internet']=next(iter(switch_01_conn.get_route_to(diccionario['ip_puerta_enlace']).values()))[0]['outgoing_interface']
        else:
            diccionario.update(switch_01_conn.cli(operaccion))

    switch_01_conn.close()
    return diccionario

def operacciones_nepalm(host, comandos_sin_interaccion,lista_comandos_con_interaccion,string_experados,respuestas_experadas):
    """
        La siguiente función aplica un string con los comandos que se quieren aplicar en un dispositivo de red mediante NAPALM
        Args:
            host (dict): Diccionario con la información de conexión del dispositivo.
            comandos_sin_interaccion (str): Comandos que se ejecutan sin necesidad de interacción.
            lista_comandos_con_interaccion (list): Lista de comandos que requieren interacción.
            string_experados (str): Cadena de texto esperada (no utilizada, incluida por compatibilidad con Netmiko).
            respuestas_experadas (str): Respuestas esperadas (no utilizada, incluida por compatibilidad con Netmiko).

        Nota:
            Las variables `string_experados` y `respuestas_experadas` no se utilizan en esta función,
            pero se incluyen por compatibilidad con Netmiko para poder abstraer dichas operaciones en la realización de tareas, ya que
            siguen un formato de entrada muy parecido.
    """


    driver = get_network_driver('ios')

    switch_01_conn = driver(**host)
    switch_01_conn.open()
    comando=""

    print(comandos_sin_interaccion)
    switch_01_conn.load_merge_candidate(config=comandos_sin_interaccion)
    print(switch_01_conn.compare_config())
    switch_01_conn.commit_config()
    if  lista_comandos_con_interaccion !=[]:
        comando=obtener_linea_posterior(comandos_sin_interaccion,"!contexto")
        print(comando)
        host={
            "username": host['username'],
            "password": host['password'],
            "device_type": "cisco_ios",
            "host": host['hostname'],
            "secret": host['optional_args']['secret']

        }

    switch_01_conn.close()
