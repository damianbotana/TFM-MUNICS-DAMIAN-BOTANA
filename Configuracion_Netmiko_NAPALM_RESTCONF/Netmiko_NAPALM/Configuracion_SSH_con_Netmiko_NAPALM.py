def telnet_to_ssh(host, lista_hosts,parametros,aplicacion_equipos_herramienta):
    hostname_equipo_aplicado=host.pop('nombre_equipo')
    lista_comandos_con_interaccion=[f"crypto key generate rsa modulus {parametros['tamano_clave_rsa']}"]


    #creacion de la clave rsa
    comandos=f"ip domain name {hostname_equipo_aplicado}.local \n"


    #aplicacion ssh en el equipo
    comandos+=f"ip ssh version 2\n"
    comandos+=f"ip ssh authentication-retries 2\n"
    comandos+=f"ip ssh time-out 60\n"
    comandos+="line vty 0 4\n"
    comandos+="transport input ssh\n"
    aplicacion_equipos_herramienta(host,comandos,[],[],[])
