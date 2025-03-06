def creacion_zonas_seguridad(nombres_zona,descripcion_zona):
    return f"zone security {nombres_zona}\ndescription {descripcion_zona}\n"

def asociar_zona_interfaz(interfaz,zona):
    return f"""
    interface {interfaz}
        zone-member security {zona}
    exit\n"""

def crear_clas_map(nombre_class_map,nombre_acl):
    return f"""
    class-map type inspect match-any {nombre_class_map}
        match access-group name {nombre_acl} \n
    """

def crear_policy_zfw(nombre_policy_map,nombre_class_map,operacion):
    return f"""
    policy-map type inspect {nombre_policy_map}
        class type inspect {nombre_class_map}
        {operacion}
        class class-default
        drop \n
    """

def asignar_politicas_zonas(nombre_zona,origen,destino,politica_nombre):
    return f"""
        zone-pair security {nombre_zona} source {origen} destination {destino}
            service-policy type inspect {politica_nombre} \n
    """
