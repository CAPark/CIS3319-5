#!/usr/bin/env python3

import socket
import pyDes as pydes
import const_auths
import time

def getDESKeyFromFile(filename):
    DES_key = None
    with open(filename, "r") as key_file:
        DES_key = key_file.readline().strip("\r\n")

    print("The shared DES Key is: " + DES_key)
    return DES_key

def startAsTgsServer(AS_key, TGS_key, V_key):
    socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (const_auths.host, const_auths.TGS_port)

    while True:
        #AS handler
        socket_.bind(server_address)
        socket_.listen()
        print("Waiting for connection...")
        connection, client_address = socket_.accept()
        print("Connection has been made.")

        received = socket_.recv(const_auths.CON_SIZE)
        AS_TS_2 = time.time()
        if(received.TS < AS_TS_2 - 60000):
            print("Invalid (timeout)")
            return
        #decrypting AS_key encryption
        key = pydes.des("DESCRYPT", pydes.CBC, AS_key,
                        pad=None, padmode=pydes.PAD_PKCS5)
        message = key.decrypt(received.content, padmode=pydes.PAD_PKCS5)
        print("Message received at AS: " + repr(message))

        #encrypt with TGS_key encryption
        key = pydes.des("DESCRYPT", pydes.CBC, TGS_key,
                        pad=None, padmode=pydes.PAD_PKCS5)
        message = key.encrypt(message)

        #create packet to return to C
        packet_AS_C = const_auths.Packet(message, AS_TS_2, None, None,
                        received.ID_TGS, const_auths.lifetime2, None)

        #send packet to C
        connection.send(packet_AS_C)

        ####################################################################
        #TGS handler
        received = socket_.recv(const_auths.CON_SIZE)
        TGS_TS_2 = time.time()
        if(received.TS < TGS_TS_2 - 60000):
            print("Invalid (timeout)")
            return
        #decrypting AS_key encryption
        key = pydes.des("DESCRYPT", pydes.CBC, TGS_key,
                        pad=None, padmode=pydes.PAD_PKCS5)
        message = key.decrypt(received.content, padmode=pydes.PAD_PKCS5)
        print("Message received at TGS: " + repr(message))

        #encrypt with TGS_key encryption
        key = pydes.des("DESCRYPT", pydes.CBC, V_key,
                        pad=None, padmode=pydes.PAD_PKCS5)
        message = key.encrypt(message)

        #create packet to return to C
        packet_TGS_C = const_auths.Packet(message, TGS_TS_2, received.ID_C,
                        received.ID_V, None, None, const_auths.lifetime4)

        #send packet to C
        connection.send(packet_TGS_C)

def main():
    AS_key = getDESKeyFromFile("keys/K_AS.txt")
    TGS_key = getDESKeyFromFile("keys/K_TGS.txt")
    V_key = getDESKeyFromFile("keys/K_V.txt")

    startAsTgsServer(AS_key, TGS_key, V_key)
    return


# This snippet of code verifies that this file was called through the command
# line and not through another python file. (reduces unnecessary errors)
if __name__ == "__main__":
    main()
