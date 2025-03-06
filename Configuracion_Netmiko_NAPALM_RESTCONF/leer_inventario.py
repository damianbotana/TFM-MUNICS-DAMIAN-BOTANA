import sys
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
from ansible.vars.manager import VariableManager
from ansible.utils.display import Display
from ansible_vault import Vault
import yaml

def load_vault_credentials(vault_file, vault_password):
    """
    Carga y descifra el archivo de Vault de Ansible.

    :param vault_file: Ruta al archivo de Vault (.yml)
    :param vault_password: Contraseña de Vault
    :return: Diccionario con las credenciales descifradas
    """
    vault = Vault(vault_password)
    with open(vault_file, 'r') as file:
        encrypted_data = file.read()
    decrypted_data = vault.load(encrypted_data)

    return decrypted_data

def get_inventory_details(inventory_file, group_name,vault_file, vault_password):
    """
    Lee el archivo de inventario de Ansible y muestra:
    - Variables globales definidas en [all:vars]
    - Hosts que pertenecen al grupo especificado, junto con sus direcciones IP (ansible_host)

    :param inventory_file: Ruta al archivo de inventario (.ini)
    :param group_name: Nombre del grupo del cual se desean listar los hosts
    """
    display = Display()
    loader = DataLoader()
    all_vars = {}

    # Inicializar InventoryManager con el archivo de inventario
    inventory = InventoryManager(loader=loader, sources=[inventory_file])

    # Cargar y descifrar las credenciales del archivo de Vault
    credentials = load_vault_credentials(vault_file, vault_password)

    # Inicializar VariableManager
    variable_manager = VariableManager(loader=loader, inventory=inventory)

    # 1. Obtener y mostrar las variables globales [all:vars]
    if 'all' in inventory.groups:
        # Se tiene que devolver el diccionario de las variables globales

        all_vars = inventory.groups['all'].vars


    else:
        display.display("\n=== No se encontraron variables globales [all:vars] ===")

    # Combinar las variables globales con las credenciales del Vault
    all_vars.update(credentials)
    # 2. Verificar si el grupo especificado existe en el inventario
    if group_name not in inventory.groups:
        display.display(f"\nError: El grupo '{group_name}' no existe en el inventario.")
        sys.exit(1)

    # 3. Obtener y mostrar los hosts del grupo especificado
    group = inventory.groups[group_name]
    hosts = group.get_hosts()

    if not hosts:
        display.display(f"\nEl grupo '{group_name}' no tiene hosts asignados.")
        sys.exit(0)

    # 4. Obtener las variables de los hosts y los grupos a los que pertenecen
    host_details = []
    for host in hosts:
        host_vars = variable_manager.get_vars(host=host)

        # Obtener las variables de los grupos a los que pertenece el host
        group_vars = {}
        for group in host.groups:
            group_vars.update(group.vars)

        # Combinar las variables del host con las variables de los grupos
        combined_vars = {**group_vars, **host_vars}

        host_details.append(combined_vars)
        #host_details.update(credentials)


    return all_vars, host_details

def obtener_variables_equipo(inventario_path, host_name):
    # Cargar el inventario
    loader = DataLoader()
    inventory = InventoryManager(loader=loader, sources=[inventario_path])
    variable_manager = VariableManager(loader=loader, inventory=inventory)

    # Obtener el host
    host = inventory.get_host(host_name)
    if not host:
        raise ValueError(f"Host {host_name} no encontrado en el inventario")

    # Obtener las variables del host
    host_vars = variable_manager.get_vars(host=host)
    return host_vars

    # 4. Opcional: Si deseas manejar variables específicas del grupo
    # Puedes descomentar el siguiente bloque para mostrar variables del grupo
    """
    group_vars = group.vars
    if group_vars:
        display.display(f"\n=== Variables del grupo '{group_name}' ===")
        for key, value in group_vars.items():
            display.display(f"{key}: {value}")
    else:
        display.display(f"\nNo hay variables definidas para el grupo '{group_name}'.")
    """

