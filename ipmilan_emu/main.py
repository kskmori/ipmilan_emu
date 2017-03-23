import socket
import traceback

from session import Session
from ipmi import RMCPPacket
from logger import Logger

UDP_IP = "0.0.0.0"
UDP_PORT = 623



def main():
    bufsize = 4096

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    session = Session.getCurrentSession() # single session only for the present
    Logger.info("Starting recvfrom:")
    while True:
        data, addr = sock.recvfrom(bufsize)
        Logger.debug("recvfrom: %s" % str(addr))
        try:
            rmcp = RMCPPacket()
            rmcp.unpack(data)
            reply = rmcp.process(session)
            if reply:
                sock.sendto(reply.pack(), addr)
                Logger.debug("sendto: %s" % str(addr))
        except Exception as e:
            Logger.error(traceback.print_exc())
    return

if __name__ == '__main__':
    main()
