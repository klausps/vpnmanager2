from backend.Router import Router, RouterConnectionError, RouterConfigError, RouterLockError
import random

class DummyDevice(Router):
    def __init__(self, host: str, user: str, passwd: str, hwmodel: str, port=830):
        """
        :param host: str, IP address or FQDN
        :param user: str
        :param passwd: str
        :param hwmodel: str
        :param port: int
        """
        super().__init__(host, user, passwd, hwmodel, port)
        self._device = None
        self._host = host
        self._cfg = None
        self._locked = False
        self._hwmodel = hwmodel
        self._isconnected = False
        self._islocked = True

    @property
    def connected(self):
        return self._isconnected

    @property
    def locked(self):
        return self._islocked

    def get_interface_information(self):
        """
        :return: dict
        """
        if self._isconnected:
            return random.randint(1, 10000)
        else:
            raise RouterConnectionError

    def get_free_unit(self, iface):
        """
        :return: int
        """
        if self._isconnected:
            rand_int = random.randint(1, 10000)
            print(f"DUMMY: Get unit on Router {self._host} iface: {iface} unit: {rand_int}")
            return rand_int
        else:
            raise RouterConnectionError

    def connect(self):
        """
        :return: boolean
        """
        if not self._isconnected:
            self._isconnected = True
            print(f"DUMMY: Connected to Router {self._host} hwmodel: {self._hwmodel}")
        return self._isconnected

    def disconnect(self):
        """
        :return: boolean
        """
        self._isconnected = False
        self._islocked = False
        print(f"DUMMY: Disconnected from Router {self._host}")
        return self._isconnected

    def get_config(self):
        if self._isconnected:
            return f"DUMMY: GET CONFIG on Router {self._host}"
        else:
            print(f"DUMMY: is disconnected")
            raise (RouterConfigError, RouterConnectionError)

    def lock_config(self):
        """
        :return: boolean
        """
        if self._isconnected:
            self._islocked = True
            print(f"DUMMY: Locked Router {self._host}")
            return self._islocked
        else:
            print(f"DUMMY: is disconnected")
            raise RouterLockError

    def unlock_config(self):
        if self._isconnected:
            print(f"DUMMY: Unlocked Router {self._host}")
            return True
        else:
            print(f"DUMMY: is disconnected")
            raise (RouterLockError, RouterConnectionError)

    def diff(self):
        if self._isconnected:
            print(f"DUMMY: GET DIFF CONFIG on Router {self._host}")
        else:
            print(f"DUMMY: is disconnected")
            raise RouterConnectionError

    def load_config(self, config, config_format):
        if self._isconnected:
            print(f"DUMMY: Loaded config on Router {self._host} Config: {config}, Config Format: {config_format}")
            return True
        else:
            print(f"DUMMY: is disconnected")
            raise (RouterConfigError, RouterConnectionError)

    def rollback(self):
        if self._isconnected:
            print(f"DUMMY: Loaded rollback config on Router {self._host}")
        else:
            print(f"DUMMY: is disconnected")
            raise RouterConnectionError
        return True

    def commit_check(self):
        if self._isconnected:
            print(f"DUMMY: Config check on Router {self._host}")
        else:
            print(f"DUMMY: is disconnected")
            raise RouterConnectionError
        return True

    def commit(self, comment=""):
        if self._isconnected:
            print(f"DUMMY: Config commited on Router {self._host} with comment {comment}")
        else:
            print(f"DUMMY: is disconnected")
            raise RouterConnectionError
        return True

    def create_ac(self, iface, unit, vlan_id, cust_id, circuit_id, bw_bits):
        if self._isconnected:
            print(f"DUMMY: CREATED AC {iface} on Router {self._host} with vlan_id :{vlan_id} unit:{unit} cust_id: {cust_id}, circuit_id: {circuit_id} bw_bits:{bw_bits}")
        else:
            print("DUMMY: is disconnected")
            raise RouterConnectionError

    def delete_ac(self, iface, unit):
        if self._isconnected:
            print(f"DUMMY: DELETE AC on Router {self._host} iface: {iface} unit: {unit}")
        else:
            print("DUMMY: is disconnected")
            raise RouterConnectionError

    def create_l2vpn(self, l2vpn_id, iface, unit, extra_community_name, site_id):
        if self._isconnected:
            print(
                f"DUMMY: CREATED L2VPN {l2vpn_id} on Router {self._host} with iface:{iface} unit:{unit} community:{extra_community_name} site: {site_id}")
        else:
            print("DUMMY: is disconnected")
            raise RouterConnectionError

    def delete_l2vpn(self, l2vpn_id, iface, unit):
        if self._isconnected:
            print(f"DUMMY: DELETED L2VPN {l2vpn_id} on Router {self._host} with iface:{iface} unit:{unit}")
        else:
            print("DUMMY: is disconnected")
            raise RouterConnectionError

    def create_trunk(self, iface, circuit_id, iface_description):
        if self._isconnected:
            print(
                f"DUMMY: CREATED TRUNK on {iface} on Router {self._host} with circuit_id {circuit_id} description {iface_description}")
        else:
            print("DUMMY: is disconnected")
            raise RouterConnectionError

    def create_l3vpnhub(self, l3vpn_id, max_prefixes):
        if self._isconnected:
            print(f"DUMMY: CREATED L3VPNHUB L3VPN_ID {l3vpn_id} max_prefixes: {max_prefixes}")
        else:
            print("DUMMY: is disconnected")
            raise RouterConnectionError

    def delete_l3vpnhub(self, l3vpn_id):
        if self._isconnected:
            print(f"DUMMY: DELETED L3VPNHub {l3vpn_id} on Router {self._host}")
        else:
            print("DUMMY: is disconnected")
            raise RouterConnectionError

    def create_l3vpnce(self, l3vpn_id, inet_prefix, inet6_prefix, peer_as, iface_unit):
        if self._isconnected:
            print(f"DUMMY: CREATED L3VPNCE L3VPN_ID {l3vpn_id} inet_prefix: {inet_prefix} inet6_prefix: {inet6_prefix} peer_as: {peer_as} iface_unit: {iface_unit}")
        else:
            print("DUMMY: is disconnected")
            raise RouterConnectionError

    def delete_l3vpnce(self, l3vpn_id, inet_prefix, inet6_prefix):
        if self._isconnected:
            print(f"DUMMY: DELETED L3VPNCE L3VPN_ID {l3vpn_id} inet_prefix: {inet_prefix} inet6_prefix: {inet6_prefix}")
        else:
            print("DUMMY: is disconnected")
            raise RouterConnectionError

    def create_evpnhub(self, evpn_id, split_horizon, designated_forwarder, route_targets=None, extended_communities=None):
        if self._isconnected:
            print(f"DUMMY: CREATED EVPNHub EVPN_ID {evpn_id} split_horizon: {split_horizon} designated_forwarder: {designated_forwarder} route_targets: {route_targets} extended_communities: {extended_communities}")
        else:
            print("DUMMY: is disconnected")
            raise RouterConnectionError

    def delete_evpnhub(self, evpn_id):
        if self._isconnected:
            print(f"DUMMY: DELETED EVPNHub EVPN_ID {evpn_id}")
        else:
            print("DUMMY: is disconnected")
            raise RouterConnectionError

    def create_evpnce(self, evpn_id, iface_unit):
        if self._isconnected:
            print(f"DUMMY: CREATED EVPNCE EVPN_ID {evpn_id} iface_unit: {iface_unit}")
        else:
            print("DUMMY: is disconnected")
            raise RouterConnectionError

    def delete_evpnce(self, evpn_id):
        if self._isconnected:
            print(f"DUMMY: DELETED EVPNCE EVPN_ID {evpn_id}")
        else:
            print("DUMMY: is disconnected")
            raise RouterConnectionError