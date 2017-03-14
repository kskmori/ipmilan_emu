import socket
import traceback

from session import Session
from ipmi import RMCPPacket

UDP_IP = "0.0.0.0"
UDP_PORT = 623



def main():
    bufsize = 4096

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    session = Session.getCurrentSession() # single session only for the present
    while True:
        data, addr = sock.recvfrom(bufsize)
        print "DEBUG: recvfrom:", addr
        try:
            rmcp = RMCPPacket()
            rmcp.unpack(data)
            reply = rmcp.process(session)
            if reply:
                print "DEBUG: sendto:", addr
                sock.sendto(reply.pack(), addr)
        except Exception as e:
            #print e
            print traceback.print_exc()
    return

if __name__ == '__main__':
    main()
