##
# Programa para el uso de la api visrus total y la clasificaioón
# muestras (5540)
##
from pathlib import Path
import datetime
import time
import pymysql
'Libreria para le manejo de archivos JSON'
import json
import argparse
import requests
import re
import os

class DataBase:
    def __init__(self):
        self.conexion = pymysql.connect(
            host='localhost',
            user='ss',
            password='ss_passV1',
            db='malware'

        )
        self.cursor = self.conexion.cursor()
        print("Conexion establecida exitosamente!")

    def select_muestra(self, id):
        query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00000` WHERE id = {}'.format(
            id)
        try:
            self.cursor.execute(query)
            muestra = self.cursor.fetchone()
            campos = []
            campos.append(muestra[0])
            campos.append(muestra[1])
            campos.append(muestra[2])
            campos.append(muestra[3])
            campos.append(muestra[4])
        except Exception as e:
            raise
        return campos
   
    #Seleccion de datos con muestras con limites: de n a n
    def seleccion_muestras_n_n(self, tabla, valor_inical, valor_final):
        limites = (valor_inical, valor_final)
        if tabla == 0:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00000` LIMIT %s,%s'
        elif tabla == 1:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00001` LIMIT %s,%s'
        elif tabla == 2:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00002` LIMIT %s,%s'
        elif tabla == 3: 
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00003` LIMIT %s,%s'
        elif tabla == 4:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00004` LIMIT %s,%s'
        else:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00005` LIMIT %s,%s'

        try:
            self.cursor.execute(query,limites)
            muestras = self.cursor.fetchall()
            lista_muestra = []
            for muestra in muestras:
                lista_muestra.append(muestra[4])
        except Exception as e:
            raise
        
        return lista_muestra 

    #Seleccion de datos con muestras con limites:
    #Primeros 100 muestras.
    def seleccion_muestras_0_100(self,seleccion):
        
        if seleccion == 0:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00000` LIMIT 100'
        elif seleccion == 1:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00001` LIMIT 100'
        elif seleccion == 2:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00002` LIMIT 100'
        elif seleccion == 3: 
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00003` LIMIT 100'
        elif seleccion == 4:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00004` LIMIT 100'
        else:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00005` LIMIT 100'

        try:
            self.cursor.execute(query)
            muestras = self.cursor.fetchall()
            lista_muestra = []
            for muestra in muestras:
                lista_muestra.append(muestra[4])
        except Exception as e:
            raise
        
        return lista_muestra

    #Consulta de todos los registros:
    def select_all_muestras(self, seleccion):
        if seleccion == 0:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00000` '
        elif seleccion == 1:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00001` '
        elif seleccion == 2:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00002` '
        elif seleccion == 3:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00003` '
        elif seleccion == 4:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00004` '
        else:
            query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00005` '

        try:
            self.cursor.execute(query)
            muestras = self.cursor.fetchall()
            list_muestras = []
            n = 0
            for muestra in muestras:
                list_muestras.append(muestra[4])
        except Exception as e:
            raise
        return list_muestras

    ##
    # Funcion que muestra los valores de las tablas. 
    # 
    ## 
    def mostrar_datos_clasificados(self, tabla, id):
        
        print("Mostrar datos")
        if tabla == 0:
            query = 'SELECT muestra, resultado, familia, consulta_json FROM `VirusTotal-00000` WHERE id = {}'.format(
            id)
        elif tabla == 1:
            query = 'SELECT muestra, resultado, familia, consulta_json FROM `VirusTotal-00001` WHERE id = {}'.format(
            id)
        elif tabla == 2:
            query = 'SELECT muestra, resultado, familia, consulta_json FROM `VirusTotal-00002` WHERE id = {}'.format(
            id)
        elif tabla == 3:
            query = 'SELECT muestra, resultado, familia, consulta_json FROM `VirusTotal-00003` WHERE id = {}'.format(
            id)
        elif tabla == 4:
            query = 'SELECT muestra, resultado, familia, consulta_json FROM `VirusTotal-00004` WHERE id = {}'.format(
            id)
        else:
            query = 'SELECT muestra, resultado, familia, consulta_json FROM `VirusTotal-00005` WHERE id = {}'.format(
            id) 
        try:
            self.cursor.execute(query)
            muestra = self.cursor.fetchone()
            campos = []
            
            campos.append(muestra[0]) 
            campos.append(muestra[1])
            campos.append(muestra[2])
            campos.append(muestra[3])
            

        except Exception as e:
            raise
        return campos

    def guardar_datos_clasificacion_familias(self,num_tabla ,muestra, resultado, familia, consulta_archivo):
       # Sintaxis para insertar datos en msyql:
       # INSERT INTO nombre_tabla (columna1, comluna2, ...) VALUES (valor1, valor2, ...)
       valores = (muestra, resultado, familia, consulta_archivo)
       if num_tabla == 0:
           query = "INSERT INTO `VirusTotal-00000`(muestra, resultado, familia, consulta_json) VALUES(%s, %s, %s, %s)"
       elif num_tabla == 1:
           query = "INSERT INTO `VirusTotal-00001`(muestra, resultado, familia, consulta_json) VALUES(%s, %s, %s, %s)"
       elif num_tabla == 2:
           query = "INSERT INTO `VirusTotal-00002`(muestra, resultado, familia, consulta_json) VALUES(%s, %s, %s, %s)"
       elif num_tabla == 3:
           query = "INSERT INTO `VirusTotal-00003`(muestra, resultado, familia, consulta_json) VALUES(%s, %s, %s, %s)"
       elif num_tabla == 4:
           query = "INSERT INTO `VirusTotal-00004`(muestra, resultado, familia, consulta_json) VALUES(%s, %s, %s, %s)" 
       else:
           query = "INSERT INTO `VirusTotal-00005`(muestra, resultado, familia, consulta_json) VALUES(%s, %s, %s, %s)" 
       
       try:
           self.cursor.execute(query, valores)
           self.conexion.commit()
           print("DATOS GUARDADOS")
       except Exception as e:
            raise 


    def elimanar_registros(self, num_tabla):
        if num_tabla == 0:
            query = "truncate `VirusTotal-00000`"
        elif num_tabla == 1:
            query = "truncate `VirusTotal-00001`"
        elif num_tabla == 2:
            query = "truncate `VirusTotal-00002`" 
        elif num_tabla == 3:
            query = "truncate `VirusTotal-00003`" 
        elif num_tabla == 4:
            query = "truncate `VirusTotal-00004`" 
        else:
            query = "truncate `VirusTotal-00005`"  
        try:
            self.cursor.execute(query)
            self.conexion.commit()
        except Exception as e:
            raise

    def close(self):
        self.conexion.close()

#Limpiar terminal:
clearConsole = lambda: os.system('cls' if os.name in ('nt', 'dos') else 'clear')

# Variables para la autentifacion de la API
# De virus totak
api_key = 'ed6515a99ff5bbfc2283bf82ee26f94aa45f1b3cad58fdc5726dc2d368b9f713'
url = "https://www.virustotal.com/api/v3/search?query="

headers = {
    "Accept": "application/json",
    "x-apikey": api_key
}
#En conocer otras abreviaciones a las 
familias_dic = {
    'A' : 'fakeinstaller',
    'B' : 'droidkungfu',
    'C' : 'plankton',
    'D' : 'opfake',
    'E' : 'gingermaster',
    'F' : 'basebridge',
    'G' : 'iconsys',
    'H' : 'kmin',
    'I' : 'fakedoc',
    'J' : 'geinimi',
    'K' : 'adrd',
    'L' : 'droidream',
    'M' : 'linuxlotoor',
    'N' : 'golddream',
    'O' : 'mobiletx',
    'P' : 'fakerun',
    'Q' : 'sendpay',
    'R' : 'gappusin',
    'S' : 'imlog',
    'T' : 'smsreg'
}

def temporizador():
    time.sleep(20)

def concatenar(url,hash):
    url_full = url + hash
    return url_full

def procesar_informacion(DB,aux_list,tabla):
    print("Funcion principañ")
    for list in aux_list:
                    a = a + 1
                    familia = True
                    print("Contador: ", a)
                    print("Muestra: ", list)
                    aux_url= concatenar(url,list)
                    print("url: " , aux_url)
                    response_json = requests.request("GET",aux_url, headers=headers)
                    consulta_dict = json.loads(response_json.content)
                    familia_query = consulta_dict['data'][0]['attributes']['popular_threat_classification']['suggested_threat_label']
                    print("Diccionario version 1: ", familia_query)
                    for key in familias_dic:
                        if re.search(familias_dic[key],familia_query):
                            familia = False
                            print(familias_dic[key].upper())
                            DB.guardar_datos_clasificacion_familias(tabla,list, familia_query, familias_dic[key].upper(), response_json.content) 
                    if familia == True:
                        print("NINGUNA") 
                        DB.guardar_datos_clasificacion_familias(tabla,list, familia_query, "NINGUNA", response_json.content)
                    temporizador()




def generar_archivo_bitacora():
    print("Realiza la bitacoras de las consultas que se hicieron")

def main():
    DB = DataBase()
    fecha = datetime.datetime.today()
    aux_list = []
    
    a = 0
    datos = {}
    #aux_campos = []
    #aux_campos = DB.select_muestra(1)
    #data['muestras'] = []
    # print("Funcion->Id:", aux_campos[0])
    
    
    opc = 0
    while opc != 's' :
            print("Opciones: \n 1) Funcion de realizar las consultas primero 100 \n 2) Funcion de realizar las consultas de un punto inical y una cantidad \n 3) Limpiar la tabla de las consultas \n Salir (s) ")
            opc = input("Seleccione una opcion: ")
           
            if(opc == '1'):
                print("Opcion 1")
                tabla = input("Seleccione una tabla de 0 - 5: ")
                tabla = int(tabla)
                aux_list = DB.seleccion_muestras_0_100(tabla)
            
                for list in aux_list:
                    a = a + 1
                    familia = True
                    print("Contador: ", a)
                    print("Muestra: ", list)
                    aux_url= concatenar(url,list)
                    print("url: " , aux_url)
                    response_json = requests.request("GET",aux_url, headers=headers)
                    consulta_dict = json.loads(response_json.content)
                    familia_query = consulta_dict['data'][0]['attributes']['popular_threat_classification']['suggested_threat_label']
                    print("Diccionario version 1: ", familia_query)
                    for key in familias_dic:
                        if re.search(familias_dic[key],familia_query):
                            familia = False
                            print(familias_dic[key].upper())
                            DB.guardar_datos_clasificacion_familias(tabla,list, familia_query, familias_dic[key].upper(), response_json.content) 
                    if familia == True:
                        print("NINGUNA") 
                        DB.guardar_datos_clasificacion_familias(tabla,list, familia_query, "NINGUNA", response_json.content)
                    temporizador()                       
                print("fin")
            
            elif(opc == '2'):
                print("Opcion 2")
                tabla = input("Seleccione una tabla de 0 - 5: ")
                tabla = int(tabla)
                inicial = input("Inicio: ")
                inicial = int(inicial) 
                cantidad = input("Cantidad: ")
                cantidad = int(cantidad)
                if cantidad < 500:
                    print("Cantidad valida")
                else:
                    print("Candidad invalida")
                    break 
                aux_lista = DB.seleccion_muestras_n_n(tabla,inicial,cantidad)
                
                print("Muesta: ", aux_lista[0])
                decision = input("Deseas continuar (s): ")
                
                if decision == 's' :
                    for lista in aux_lista:
                        a = a + 1
                        familia = True
                        print("Contador: " ,cantidad,'/',a)
                        print("Muestra: ", lista)
                        aux_url= concatenar(url,lista)
                        print("url: " , aux_url)
                        response_json = requests.request("GET",aux_url, headers=headers)
                        consulta_dict = json.loads(response_json.content)
                        familia_query = consulta_dict['data'][0]['attributes']['popular_threat_classification']['suggested_threat_label']
                        print("Diccionario version 1: ", familia_query)
                        for key in familias_dic:
                            if re.search(familias_dic[key],familia_query):
                                familia = False
                                print(familias_dic[key].upper())
                                DB.guardar_datos_clasificacion_familias(tabla,lista, familia_query, familias_dic[key].upper(), response_json.content) 
                        if familia == True:
                            print("NINGUNA") 
                            DB.guardar_datos_clasificacion_familias(tabla,lista, familia_query, "NINGUNA", response_json.content)
                        
                        temporizador()

            elif(opc == '3'):
                print("Opcion 3")
                tabla = input("Seleccione una tabla de 0 - 5: ")
                tabla = int(tabla)
                DB.elimanar_registros(tabla)

            elif(opc == '4'):
                print('Opcion 4')
                #
                tabla = input("Seleccionar tabla: 0-5: ")
                tabla = int(tabla)
                id = input("ID MUestra: ")
                id = int(id)
                
                aux_list = DB.mostrar_datos_clasificados(tabla, id)
                print("Muestra: ")
                print(aux_list[0])
    
                print("Resultado: ")
                print(aux_list[1])

                print("Familia: ")
                print(aux_list[2])

                print("Archivo JSON: ")
                arch_json = json.loads(aux_list[3])
                print(json.dumps(arch_json['data'][0]['attributes'],indent=3))
                
                
            
            elif(opc == 's'):
                print("Opcion 4: Salir")
            else:
                print("No hay opcion para ese dato")
            #clearConsole()

    

if __name__ == '__main__':
    main()