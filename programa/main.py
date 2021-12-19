##
# Programa para el uso de la api visrus total y la clasificaioón
# muestras (5540)
##
import time
import pymysql
'Libreria para le manejo de archivos JSON'
import json
import base64
import argparse
import requests
import pickle
import re


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

        #    print("Id:", muestra[0])
        #    print("File_name:", muestra[1])
        #    print("Md5:", muestra[2])
        #    print("Sha1:", muestra[3])
        #    print("Sha256:", muestra[4])

        except Exception as e:
            raise
        return campos

    def select_all_muestras(self):
        query = 'SELECT id, file_name, md5, sha1, sha256 FROM `Drebin-00000` '
        try:
            self.cursor.execute(query)
            muestras = self.cursor.fetchall()
            list_muestras = []
            n = 0
            for muestra in muestras:
                # print("Id:",muestra[0])
                # print("File_name:",muestra[1])
                # print("Md5:",muestra[2])
                # print("Sha1:",muestra[3])
                # print("Sha256:",muestra[4])
                # print("____________________\n")
                list_muestras.append(muestra[2])
        except Exception as e:
            raise
        return list_muestras


# DB.select_all_muestras()
time_duration = 15
#print("Num muestras totales = ", auxs)

a = 0
#print("Muestras ejemplos:", aux_list[1])
# Variables para la autentifacion de la API
# De virus totak
api_key = 'ed6515a99ff5bbfc2283bf82ee26f94aa45f1b3cad58fdc5726dc2d368b9f713'
url = "https://www.virustotal.com/api/v3/search?query="

headers = {
    "Accept": "application/json",
    "x-apikey": api_key
}

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

##
# for list in aux_list:
#    a = a + 1
#   if(a < 10):
#        print("Indice:", a)
#        print("Prueba: ", list)
#       temporizador()
# #

def main():
    DB = DataBase()
    # DB.select_muestra(1)
    aux_list = []
    aux_campos = []
    aux_campos = DB.select_muestra(1)
    #print("Funcion->Id:", aux_campos[0])
    aux_list = DB.select_all_muestras()
    print("Dato 1:", aux_list[0])
    aux_url= concatenar(url,aux_list[0])
    print("url: " , aux_url)
    response = requests.request("GET",aux_url, headers=headers) 
    query_dict = json.loads(response.content)
    print("Dicionario del query:\n", query_dict.keys())
    familia_query = query_dict['data'][0]['attributes']['popular_threat_classification']['suggested_threat_label']
    print("Diccionario version 1:\n", familia_query)
    for key  in  familias_dic:
        if(familias_dic[key] == familia_query):
            print('concide o tiene una subcadena')




    

if __name__ == '__main__':
    main()
