from scapy.layers.inet import *

if __name__ == '__main__':
    print("Loading ...\n")

    #  THEORY
    #
    # Client and server variable names:
    #
    # c_ip = IP, c_port = port, c_seq = seq  # , c_ack = ack #
    # s_ip = IP, s_port = port, s_seq = seq  # , s_ack = ack #
    #
    # Handshake:
    # c_ip: c_port -> s_ip: s_port, SYN, c_seq, c_ack(=0)
    # s: ip:s_port -> c_ip: c_port, SYN / ACK, s_seq, s_ack = (c_seq + 1)
    # c_ip: c_port -> s_ip: s_port, ACK, c_seq + 1, c_ack = (s_seq + 1)

    from scapy.all import *

    sport = random.randint(1024, 65535)

    ip = IP(src="192.168.1.13", dst="192.168.1.40")

    # SYN
    SYN = TCP(sport=sport, dport=80, flags="S", seq=1000)
    print("\n####### SYN #######")
    print("Seq = " + str(SYN.seq))
    print("Ack = " + str(SYN.ack))
    print("###################\n")

    # SYNACK
    SYNACK = sr1(ip / SYN)
    print("\n####### SYNACK #######")
    print("Seq = " + str(SYNACK.seq))
    print("Ack = " + str(SYNACK.ack))
    print("###################\n")

    # ACK
    ACK = TCP(sport=sport, dport=80, flags="A", seq=SYN.seq + 1, ack=SYNACK.seq + 1)
    print("\n####### ACK #######")
    print("Seq = " + str(ACK.seq))
    print("Ack = " + str(ACK.ack))
    print("###################\n")

    send(ip / ACK)
