import socket
import sys
import struct
import urllib.parse
import time
import random
from collections import deque

HTTP_VER = '1.0'  # We use 1.0 to get rid of chunked encoding
DST_PORT = 80  # We send on 80 for HTTP 1.0
NO_FLAG = 0  # Denotes we want a 0 bit in a given tcp flag
FLAG = 1  # Denotes we want a 1 bit in a given tcp flag
SAF_DATA = bytes('', 'utf-8')  # Data for when we send a SYN, ACK, or FIN request


# Gets our command line argument
def getArg():
    try:
        return sys.argv[1]
    except IndexError:
        print("Please input command line arguments in the form './rawhttpget <url>'")
        exit()


# Creates a socket meant for sending raw packets with the IPPROTO_RAW specification
def createSendSock() -> socket.socket:
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except Exception as e:
        print("Could not create sending socket - Error: %s" % e)
        exit()


# Creates a socket meant for receiving raw packets with the IPPROTO_TCP specification
def createReceiveSock() -> socket.socket:
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except Exception as e:
        print("Could not create receiving socket - Error: %s" % e)
        exit()


# given data in the form of a packed packet, extracts the IP header
def ipFromPacket(packet):
    if len(packet) < 20:
        return None
    iphdr = packet[:20]
    header = struct.unpack('!BBHHHBBH4s4s', iphdr)
    return header


# given data in the form of a packed packet, extracts the TCP header
def tcpFromPacket(packet):
    if len(packet) < 40:
        return None
    tcphdr = packet[20:40]
    tcphdr = struct.unpack('!HHLLBBHHH', tcphdr)
    return tcphdr


# given data in the form of a packed packet, extracts the MSS
def mssFromPacket(packet):
    if len(packet) < 44:
        return None
    # mss is 40:44, lsb is 42:44 which is what we care about
    mss = packet[42:44]
    mss = struct.unpack('!H', mss)
    return mss


# Returns the address of the local machine
def getLocalIP():
    try:
        # connects to DNS resolver and then pulls the value of our IP from that connection
        temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp.connect(("8.8.8.8", 80))
        value = temp.getsockname()[0]
        temp.close()
        return value
    except Exception as e:
        print("Error finding source IP - Error: %s" % e)
        exit()


# Returns the destination IP address given a hostname
def getDestIP(host: str):
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        print("Error finding destination IP - Error: %s" % e)
        exit()


# calculates a packet's checksum based on the sum of ones complement of all 16 bit words in the header
# research on this algorithm comes mainly from this link 'packetmania.net/en/2021/12/26/IPv4-IPv6-checksum' as well
# as the RFC 951 specification
def checksum(packet):
    # we only want to deal with even length packets, so lets pad our data
    packet = packet if (len(packet) % 2 == 0) else packet + b'\0'
    check = 0
    # loop through the packet 2 bytes at a time
    for i in range(0, len(packet), 2):
        #  0 ----- 8  9 ----- 16  #
        #  packet[i]  packet[i+1] #
        #  we want to construct our word on these values
        word = packet[i] + (packet[i+1] << 8)
        check += word

    # loop again taking 16 bit shifts until we have all 0's
    while check >> 16:
        # take the existing bits and add to the bitshift
        check = (check & 0xffff) + (check >> 16)

    # last complementation
    checksum = ~check
    return checksum & 0xffff

# class for constructing HTTP GET requests
class HTTPGET:
    def __init__(self, url, ver):
        # we offload to the inbuilt urllib library for extracting the right parts of the url
        # ex url: https://david.choffnes.com/classes/cs4700sp22/project4.php
        self.parsed = urllib.parse.urlparse(url)  # library's format of a parsed url
        self.host = self.parsed.netloc  # host, ex: david.choffnes.com
        self.path = self.parsed.path  # path, if there is one, ex: /classes/cs4700sp22/project4.php
        self.resource = self.parseResource() # resource if there is one, index.html if not, ex: project4.php
        self.ver = ver  # http version, ex 1.0, 1.1
        self.message = self.constructGet()  # our final get request

    def parseResource(self):
        # if our path is the root we assume index.html, otherwise get the rightmost value of the path
        if '/' not in self.path:
            return 'index.html'
        return 'index.html' if self.path == '/' else self.path[self.path.rindex('/')+1:]

    def constructGet(self):
        # GET / HTTP/1.1\r\nHost: david.choffnes.com\r\n\r\n
        message = 'GET ' + self.path + ' HTTP/' + self.ver + '\r\n' + 'Host: ' + self.host + '\r\n\r\n'
        return message

    def verify200Ok(self, toverify):
        if bytes('HTTP/1.1 200 OK\r\n', 'ascii') in toverify:
            return True
        else:
            print('ERROR IN GET REQUEST: DID NOT RECEIVE HTTP 200 OK')
            exit()


# class for constructing TCP packets
class TCPPacket:
    # constructs a TCP packet, assumes that our data has been packed
    def __init__(self, srcprt, dstprt, seqnum, acknum, ack, push, reset, sync, fin, src_ip, dst_ip, data):
        self.srcprt = srcprt  # our source port
        self.dstprt = dstprt  # our destination port
        self.seqnum = seqnum  # current sequence number
        self.acknum = acknum  # current acknowledgement number
        # 5 words but we want it shifted
        self.doff = (5 << 4)  # our data offset, shifted
        self.rsv = 0  # reserved bits that we dont care about
        # URG | ACK | PSH | RST | SYN | FIN
        # 32  | 16  | 8   | 4   | 2   | 1
        self.urgent = 0  # urgent flag, we don't use this
        self.ack = ack  # acknowledgment flag
        self.push = push  # push flag, we might use this
        self.reset = reset  # reset flag, we might use this
        self.sync = sync  # syn flag
        self.fin = fin  # fin flag
        # we want to pack these all together as one 'flags' section
        self.flags = self.fin + (self.sync << 1) + (self.reset << 2) + (self.push << 3) + (self.ack << 4) + (self.urgent << 5)
        self.wndsize = socket.htons(10000)  # advertised window size
        self.check = 0  # dummy checksum
        self.urgptr = 0  # not used as we dont use urgent
        self.temp, self.totlen = self.calculatePseudoTCPData(src_ip, dst_ip, data)  # temporary packed packet + packlen
        self.check = checksum(self.temp)  # we calculate our checksum based on the temporary packet
        # NOTE: when we pack this one we don't want our checksum to be rearranged, this will cause issues with endian
        self.packet = struct.pack('!HHLLBBH', self.srcprt, self.dstprt, self.seqnum, self.acknum, self.doff, self.flags,
                             self.wndsize) + struct.pack('H', self.check) + struct.pack('!H', self.urgptr) + data

    def calculatePseudoTCPData(self, src_ip, dst_ip, data):
        srcip = socket.inet_aton(src_ip)  # convert src ip
        dstip = socket.inet_aton(dst_ip)  # convert dst ip
        rsv = 0  # we don't use these
        protocol = socket.IPPROTO_TCP  # we use IPPROTO_TCP as our protocol in IP
        totlen = 20 + len(data)  # 20 bytes for our tcp header + whatever data we have
        psdhdr = struct.pack('!4s4sBBH', srcip, dstip, rsv, protocol, totlen)  # pseudoheader calculation
        # calculate our tcp header with a dummy checksum
        tcphdr = struct.pack('!HHLLBBHHH', self.srcprt, self.dstprt, self.seqnum, self.acknum, self.doff,
                             self.flags,
                             self.wndsize, self.check, self.urgptr)
        # our dummy packet is the combination of our headers
        temp = psdhdr + tcphdr + data
        return temp, totlen


# class for constructing IP packets
class IPPacket:
    def __init__(self, source_ip, dest_ip, tcp: TCPPacket):
        self.hdrlen = 5  # gives our header length in bytes
        self.version = 4  # gives our version number, ipv4
        self.tos = 0  # type of service
        self.totlen = 20 + tcp.totlen  # we want the length of the whole packet, ip + tcp
        self.id = 0  # fragmentation id, we don't use this
        self.fragoff = 0  # fragmentation offset, we don't use this
        self.ttl = 200  # time to live, 200 seems like a good number
        self.proto = socket.IPPROTO_TCP  # this is our protocol
        self.srcip = socket.inet_aton(source_ip)  # convert our source ip to network bytes
        self.dstip = socket.inet_aton(dest_ip)  # convert our destination ip to network bytes
        self.ihl_ver = (self.version << 4) + self.hdrlen  # concatenate our header length and version into one arg
        self.check = 0
        # pack a pseudoheader so we can calculate our checksum
        self.psdhdr = struct.pack('!BBHHHBBH4s4s', self.ihl_ver, self.tos, self.totlen, self.id, self.fragoff, self.ttl,
                                  self.proto, self.check, self.srcip, self.dstip)
        self.check = checksum(self.psdhdr)  # calculate our checksum from the pseudoheader
        # use the checksum we just calculated and pack again
        self.finalhdr = struct.pack('!BBHHHBBH4s4s', self.ihl_ver, self.tos, self.totlen, self.id, self.fragoff, self.ttl,
                                  self.proto, self.check, self.srcip, self.dstip)
        self.tcp = tcp  # store our tcp so we can access seq and ack nums
        self.packet = self.finalhdr + tcp.packet  # add our packed version to the tcp headers packed version


# class for constructing various types of packets
class PacketCreator:
    def __init__(self, srcprt, dstprt, srcip, dstip):
        self.srcprt = srcprt
        self.dstprt = dstprt
        self.srcip = srcip
        self.dstip = dstip

    def constructPacket(self, seqnum, acknum, ack, push, reset, sync, fin, data):
        tcphdr = TCPPacket(self.srcprt, self.dstprt, seqnum, acknum, ack, push, reset, sync, fin, self.srcip,
                           self.dstip, data)
        iphdr = IPPacket(self.srcip, self.dstip, tcphdr)
        return iphdr

    def constructSyn(self, seqnum, acknum):
        return self.constructPacket(seqnum, acknum, NO_FLAG, NO_FLAG, NO_FLAG, FLAG, NO_FLAG, SAF_DATA)

    def constructAck(self, seqnum, acknum):
        return self.constructPacket(seqnum, acknum, FLAG, NO_FLAG, NO_FLAG, NO_FLAG, NO_FLAG, SAF_DATA)

    def constructAckFin(self, seqnum, acknum):
        return self.constructPacket(seqnum, acknum, FLAG, NO_FLAG, NO_FLAG, NO_FLAG, FLAG, SAF_DATA)

    def constructFin(self, seqnum, acknum):
        return self.constructPacket(seqnum, acknum, NO_FLAG, NO_FLAG, NO_FLAG, NO_FLAG, FLAG, SAF_DATA)

    def constructDataPacket(self, seqnum, acknum, data):
        return self.constructPacket(seqnum, acknum, FLAG, NO_FLAG, NO_FLAG, NO_FLAG, NO_FLAG, data)


# create our connection manager
# THINGS TO DO:

# - send a packet - DONE
# - receive a packet and verify its information - STILL NEED CHECKSUM
# - update seq, ack numbers - DONE
# - complete the threeway handshake - DONE
# - send our message - DONE
# - receive the response - DONE
# - teardown the connection - DONE (maybe last ack issue)
# - reconstruct our data - DONE

class Manager:
    def __init__(self, url):
        self.ssock = createSendSock()  # our sending socket
        self.rsock = createReceiveSock()  # our receiving socket
        # give ourselves a random range of ports
        self.srcprt = random.randint(40000, 45000)
        self.dstprt = DST_PORT  # our destination port, usually 80
        self.http = HTTPGET(url, HTTP_VER)  # http get creation utility
        self.srcip = getLocalIP()  # local ip
        self.dstip = getDestIP(self.http.host)  # destination ip
        self.address = self.dstip, self.dstprt  # (destip, destport) tuple for sendto
        self.packetgen = PacketCreator(self.srcprt, self.dstprt, self.srcip, self.dstip)  # packet creation object
        self.seqnum = 0  # current sequence number
        self.acknum = 0  # current acknowledgement number
        self.timelast = time.time()  # time of last packet sent
        self.mss = 0  # current maximum segment size
        self.cwnd = 1  # current congestion window size
        self.packetsToSend = deque([])  # stores the packets that we need to send
        self.lastIpHdr = None  # stores the last packet we sent
        self.packets = {}  # packet dictionary based on { acknum : rawpacket }
        self.incack = 1  # we want to increment our ack in the twhs
        self.recving = 0  # we are not receiving our response yet

    # sends a tries to send a packet, if it gets an exception it will exit
    def trySendPacket(self):
        try:
            self.lastIpHdr = self.packetsToSend.pop()
            #print(tcpFromPacket(self.lastIpHdr.packet))
            if self.lastIpHdr is not None:
                self.ssock.sendto(self.lastIpHdr.packet, self.address)
                self.timelast = time.time()
        except Exception as e:
            print('Error while sending data: %s' %e)
            exit()

    # returns true if the destination ip and destination port of the given packet are our source port and source ip
    def verifyDestIPPort(self, packet):
        iphdr = ipFromPacket(packet)
        tcphdr = tcpFromPacket(packet)
        return socket.inet_ntoa(iphdr[8]) == self.dstip and tcphdr[0] == self.dstprt

    # returns true if the acknowledgement number of the received packet is correct
    def verifyAck(self, recvtcphdr):
        if (self.lastIpHdr.tcp.seqnum == 0):
            return recvtcphdr[3] == self.lastIpHdr.tcp.seqnum + self.lastIpHdr.tcp.totlen - 20 + 1
        return recvtcphdr[3] == self.lastIpHdr.tcp.seqnum + self.lastIpHdr.tcp.totlen - 20

    # returns true if the sequence number of the received packet is correct
    def verifySeq(self, recvtcphdr):
        # in this case, we need to set our expected ack, thus it is always true
        if self.lastIpHdr.tcp.seqnum == 0 or self.lastIpHdr.tcp.seqnum == 1:
            return True
        else:
            return recvtcphdr[2] == self.lastIpHdr.tcp.acknum

    # returns true if the sequence and acknowledgement numbers correspond to the last packet we sent
    def verifySeqAck(self, packet):
        recvtcphdr = tcpFromPacket(packet)
        return self.verifyAck(recvtcphdr)  # and self.verifySeq(recvtcphdr)

    # determines whether the checksums of the given packet are correct
    def verifyChecksums(self, packet):
        ip_fields = list(ipFromPacket(packet))
        given_ip_checksum = ip_fields[7]
        ip_fields[7] = 0
        print(*ip_fields)
        new_ip_header = struct.pack('BBHHHBBH4s4s', *ip_fields)
        calculated_ip_checksum = checksum(new_ip_header)

        # if 44 we have mss
        if len(packet) != 44:
            tcp = packet[20:40]
            tcp_fields = list(struct.unpack('!HHLLBBHHH', tcp))
            given_tcp_checksum = tcp_fields[7]
            tcp_fields[7] = 0
            source_ip = ip_fields[8]
            dest_ip = ip_fields[9]
            reserved = 0
            protocol = socket.IPPROTO_TCP
            length = 20 + len(packet[40:])
            psdhdr = struct.pack('!4s4sBBH', source_ip, dest_ip, reserved, protocol, length)
            new_tcp_header = struct.pack('!HHLLBBHHH', *tcp_fields)
            data = packet[40:]
            tcp_packet = psdhdr + new_tcp_header + data
            calculated_tcp_checksum = checksum(tcp_packet)
            print(int(given_ip_checksum), int(calculated_ip_checksum))
            return (calculated_ip_checksum == int(given_ip_checksum)) and (calculated_tcp_checksum == int(given_tcp_checksum))
        return True

    # updates our seq and acknums based on the last packet
    def setAckSeqNumsSend(self, packet):
        # 16 = 10000 where the 1 corresponds to the ack flag
        # 18 = 10010 where 1 corresponds to ack and syn
        # 25 = 11001 where 1 corresponds to ack psh fin
        tcphdr = tcpFromPacket(packet)
        if ((tcphdr[5] == 16) or (tcphdr[5] == 18) or (tcphdr[5] == 25)) and not self.incack:
            # set our sequence to their last acknowledgement number
            self.seqnum = tcphdr[3]
            # set our ack to their last sequence number
            self.acknum = tcphdr[2]
        else:
            self.seqnum = tcphdr[3]
            self.acknum = tcphdr[2] + 1

    # sets the acknum based on the number the server sends
    def setAckReceived(self, packet):
        self.acknum = self.acknum + len(packet[40:]) - 1

    # receives packets until it gets the one that is supposed to come next
    def recvPacket(self):
        packet = None
        found = False
        # go until we find the right packet
        while not found:
            # if we haven't gotten the right one in a minute
            if time.time() - self.timelast > 60:
                # put our packet back in the queue at the front
                self.packetsToSend.append(self.lastIpHdr)
                # send our last packet again
                self.cwnd = 1  # no ACK within a minute, reset cwnd
                self.trySendPacket()
            # receive the next packet
            packet = self.rsock.recv(65565)
            if not self.verifyDestIPPort(packet):
                continue
            if not self.verifyChecksums(packet):
                print('checksums failed')
                continue
            if not self.verifySeqAck(packet):
                continue
            self.setAckSeqNumsSend(packet)
            found = True
        return packet

    # performs the threeway handshake
    def threewayHandShake(self):
        # our SYN message
        self.packetsToSend.appendleft(self.packetgen.constructSyn(self.seqnum, self.acknum))
        self.trySendPacket()
        packet = self.recvPacket()
        self.mss = mssFromPacket(packet)[0]
        self.packetsToSend.appendleft(self.packetgen.constructAck(self.seqnum, self.acknum))
        self.trySendPacket()
        self.incack = 0

    # sends all of our get request
    def sendGet(self):
        # construct our get request
        get = bytes(self.http.constructGet(), 'utf-8')
        # string pointer to 0th index
        currentIndex = 0
        # iterate until our index has covered our get
        while currentIndex < len(get):
            # calculate our bandwidth available to send through
            availableBandwidth = self.mss * self.cwnd
            # if we still have bandwidth to send
            while availableBandwidth > 0 and currentIndex < len(get):
                # add the next MSS worth of our get to the queue of packets to send
                fragment = get[currentIndex:currentIndex+self.mss]
                self.packetsToSend.appendleft(self.packetgen.constructDataPacket(self.seqnum, self.acknum, fragment))
                # decrement our bandwidth by an MSS
                availableBandwidth -= self.mss
                # increment our index by an MSS
                currentIndex += self.mss
            # if we have any more of our get request to send
            while len(self.packetsToSend) > 0:
                # send a packet
                self.trySendPacket()
                packet = self.recvPacket()
                self.cwnd = min(self.cwnd + 1, 1000)

    # checks to see if the server sent us a fin/psh/ack
    def serverClosesConn(self, packet):
        tcphdr = tcpFromPacket(packet)
        return tcphdr[5] == 25

    # acks the servers FIN, and sends a fin of our own
    def teardown(self):
        # increment our ack 2 more, this gets it inline with the last packet
        self.acknum += 2
        # ack their fin
        self.packetsToSend.appendleft(self.packetgen.constructAck(self.seqnum, self.acknum))
        self.trySendPacket()
        # send our fin
        self.packetsToSend.appendleft(self.packetgen.constructFin(self.seqnum, self.acknum))
        self.trySendPacket()

    # receives all of the packets we need to
    def recvResponse(self):
        self.recving = 1
        while True:
            packet = self.recvPacket()
            self.packets[self.lastIpHdr.tcp.acknum] = packet[40:]
            self.setAckReceived(packet)
            if self.serverClosesConn(packet):
                self.teardown()
                self.reconstruct()
                self.closeSockets()
                break
            else:
                self.packetsToSend.appendleft(self.packetgen.constructAck(self.seqnum, self.acknum))
                self.trySendPacket()

    # reconstructs the response from the server
    def reconstruct(self):
        bytearr = b''
        with open(self.http.resource, 'wb') as file:
            for key in sorted(self.packets):
                bytearr += self.packets[key]
            self.http.verify200Ok(bytearr)
            bytearr = bytearr[bytearr.find(b'\r\n\r\n')+4:]
            file.write(bytearr)

    # closes our sockets
    def closeSockets(self):
        self.rsock.close()
        self.ssock.close()

if __name__ == '__main__':
    url = getArg()
    manager = Manager(url)
    manager.threewayHandShake()
    manager.sendGet()
    manager.recvResponse()




