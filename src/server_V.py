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

def startVServer(V_key):
    socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (const_auths.host, const_auths.V_port)

    while True:
        #V handler
        socket_.bind(server_address)
        socket_.listen()
        print("Waiting for connection...")
        connection, client_address = socket_.accept()
        print("Connection has been made.")

        received = socket_.recv(const_auths.CON_SIZE)
        V_TS_2 = time.time()
        if(received.TS < V_TS_2 - 60000):
            print("Invalid (timeout)")
            return
        #decrypting V_key encryption
        key = pydes.des("DESCRYPT", pydes.CBC, V_key,
                        pad=None, padmode=pydes.PAD_PKCS5)
        message = key.decrypt(received.content, padmode=pydes.PAD_PKCS5)
        print("Message received at V: " + repr(message))

        #create packet to return to C
        message = V_TS_2 + 1000
        packet_V_C = const_auths.Packet(message, None, None, None,
                        None, None, None)

        #send packet to C
        connection.send(packet_V_C)

def main():
    V_key = getDESKeyFromFile("keys/K_V.txt")

    startVServer(V_key)
    return


# This snippet of code verifies that this file was called through the command
# line and not through another python file. (reduces unnecessary errors)
if __name__ == "__main__":
    main()
