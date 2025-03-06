import requests
from requests.auth import HTTPBasicAuth


def operacciones_restconf(url,usuario,contrasena,data_json):

    """
        Realiza operaciones RESTCONF para aplicar configuraciones en un dispositivo de red.
        Args:
            url (str): La URL del endpoint RESTCONF.
            usuario (str): Nombre de usuario para la autenticación básica.
            contrasena (str): Contraseña para la autenticación básica.
            data_json (dict): El modelo YANG en formato JSON necesario para la aplicación de una configuración en el dispositivo.
        Returns:
            None
        Imprime mensajes indicando el resultado de la operación:
            - "Configuration applied successfully." si la configuración se aplica correctamente.
            - "Failed to apply configuration. Status code: {response.status_code}" si la configuración falla, junto con el código de estado y el texto de la respuesta.
    """

    headers = {
        'Content-Type': 'application/yang-data+json',
        'Accept': 'application/yang-data+json'
    }
    auth = HTTPBasicAuth(usuario, contrasena)


    requests.packages.urllib3.disable_warnings()
    response = requests.post(url, headers=headers, auth=auth, data=data_json, verify=False)

    if response.status_code == 201:
        print("Configuration applied successfully.")
    #se prueba realizar la peticion path en caso que el elemento ya exisitia para actualizar dich valor
    elif response.status_code == 400 or response.status_code == 409:
        print(url)
        print(data_json)
        response2 = requests.patch(url, headers=headers, auth=auth, json=data_json, verify=False)
        if response2.status_code == 201:
            print("Configuration applied successfully.")
        print(response2.text)

    else:
        print(f"Failed to apply configuration. Status code: {response.status_code}")
        print(response.text)

def obtener_informacion_restconf(url,usuario,contrasena):
    """
        Obtiene información de un dispositivo de red utilizando RESTCONF.
        Args:
            url (str): La URL del dispositivo de red para la solicitud RESTCONF.
            usuario (str): El nombre de usuario para la autenticación básica HTTP.
            contrasena (str): La contraseña para la autenticación básica HTTP.
        Returns:
            dict: La respuesta JSON del dispositivo de red si la solicitud es exitosa.
            None: Si la solicitud falla, imprime el código de estado y el texto de la respuesta.
        Nota:
            Esta función desactiva las advertencias de verificación SSL de urllib3 y no verifica los certificados SSL.
    """

    headers = {
        'Content-Type': 'application/yang-data+json',
        'Accept': 'application/yang-data+json'
    }
    auth = HTTPBasicAuth(usuario, contrasena)


    requests.packages.urllib3.disable_warnings()
    response = requests.get(url, headers=headers, auth=auth, verify=False)
    if response.status_code == 200:
        print("Configuration applied successfully.")
        return response.json()
    else:
        print(f"Failed to apply configuration. Status code: {response.status_code}")
        print(response.text)
