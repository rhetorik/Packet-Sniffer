class filter:
    def __init__(self):
        self.ip_src = "any"
        self.ip_dest = "any"
        self.mac_src = "any"
        self.mac_dest = "any"
        self.network_proto = ["any"]
        self.transport_proto = ["any"]
    
    def verify(self, ethernet_header, ip_header, transport_header):
        if (not ip_header and not transport_header):
            if self.network_proto[0] != "any" or self.transport_proto[0] != "any":
                return False
            if self.ip_src != "any" or self.ip_dest != "any":
                return False
            if self.mac_src != "any" or self.mac_dest != "any":
                return False
            else:
                return True
        if self.mac_dest != "any" and ethernet_header["dest"] != self.mac_dest:
            return False
        if self.mac_src != "any" and ethernet_header["src"] != self.mac_src:
            return False
        if self.network_proto[0] != "any" and ip_header["type"] not in self.network_proto:
            return False
        if self.ip_src != "any" and ip_header["ip_src"] != self.ip_src:
            return False
        if self.ip_dest != "any" and ip_header["ip_dest"] != self.ip_dest:
            return False
        if self.transport_proto[0] != "any" and transport_header["type"] not in self.transport_proto:
            return False
        return True
