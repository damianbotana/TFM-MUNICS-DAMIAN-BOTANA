from netmiko import ConnectHandler

def convertir_comandos(comando_string):
    lineas = comando_string.splitlines()
    comandos = []
    for linea in lineas:
        linea_limpia = linea.strip()
        if linea_limpia and not linea_limpia.startswith('!'):
            comandos.append(linea_limpia)
    return comandos

def  lectura_datos_netmiko(host,comandos,informacion_obtenida):
     """
        Funcion que obtiene la información espefica de un dispositivo mediante una conexion,
        para la obtencion de la informacion se realiza una lista de comandos que se guardan en un diccionario que se pasa
        como parametro una lista de palabras que representaran la clave del diccionario que se utilizara para obtener la informacion
        lo que se devuelve es un diccionario con la informacion obtenida

     """
     global total_read
     start_time = time.time()
     host_copy = host.copy()
     if 'nombre_equipo' in host_copy:
        host_copy.pop('nombre_equipo')
     connection = ConnectHandler(**host_copy)
     which_prompt = connection.find_prompt()
     resultados={}
     if '>' in which_prompt:
        connection.enable()

     for comando,palabra_guardar in zip(comandos,informacion_obtenida):
         print(comando)
         resultado=connection.send_command(comando)
         print(connection.send_command(comando))
         resultados[palabra_guardar]=resultado

     if connection.check_config_mode:
        connection.exit_config_mode()

     connection.disconnect()

     return resultados

def operacciones_netmiko(host, comandos_sin_interaccion,lista_comandos_con_interaccion,string_experados,respuestas_experadas):
    """
        Realiza configuraciones en dispositivos de red utilizando Netmiko.
        Args:
            host (dict): Diccionario con los detalles de conexión del dispositivo (host, username, password, device_type).
            comandos_sin_interaccion (str): Comandos que se ejecutan sin necesidad de interacción adicional.
            lista_comandos_con_interaccion (list): Lista de comandos que requieren interacción adicional.
            string_experados (list): Lista de strings esperados como respuesta a los comandos interactivos.
            respuestas_experadas (list): Lista de respuestas que se deben enviar en función de los strings esperados.
        Returns:
            None
        Funcionalidad:
            - Establece una conexión con el dispositivo de red utilizando Netmiko.
            - Si el prompt contiene '>', cambia al modo Priv EXEC.
            - Entra en modo de configuración global si no está ya en ese modo.
            - Ejecuta los comandos sin interacción si se proporcionan.
            - Ejecuta los comandos interactivos y responde según los strings esperados y las respuestas esperadas.
            - Sale del modo de configuración global si está en ese modo.
            - Desconecta la sesión de Netmiko.
    """



    #realizacion conexion netmiko
    connection = ConnectHandler(**host)
    which_prompt = connection.find_prompt()
    if '>' in which_prompt:
        connection.enable() # Go to Priv EXEC mode only 'if' '>' is present in the output

    if not connection.check_config_mode():
            # Entrar en modo de configuración global
            connection.config_mode()

    #en caso de recibir un texto en blanco como comando significa que fue lllamada por otra funcion para la realizacion de las operacciones interactivas
    if comandos_sin_interaccion != "":
        print(connection.send_config_set(convertir_comandos( comandos_sin_interaccion),exit_config_mode=False))

    if lista_comandos_con_interaccion !=[]:
         for comando,experado,respuesta in zip(lista_comandos_con_interaccion,string_experados,respuestas_experadas):
                print(comando)
                print( connection.send_command_timing(comando))
                for elemento_respuata in respuesta:
                    print(elemento_respuata)
                    print(connection.send_command_timing(elemento_respuata))

    if connection.check_config_mode:
        connection.exit_config_mode()
    connection.disconnect()



