from abc import ABC, abstractmethod


class RouterConnectionError(Exception):
    pass


class RouterAuthError(Exception):
    pass


class RouterConfigError(Exception):
    pass


class RouterLockError(Exception):
    pass


class Router(ABC):
    def __init__(self, host: str, user: str, passwd: str, hwmodel: str, port: int):
        """
        :param host: str, IP address or FQDN
        :param user: str
        :param passwd: str
        :param hwmodel: str
        :param port: int
        """
        self._host = host
        self._user = user
        self._passwd = passwd
        self._port = port
        self._hwmodel = hwmodel

    @property
    def host(self):
        return self._host

    @property
    def user(self):
        return self._user

    @property
    def hwmodel(self):
        return self._hwmodel

    @property
    @abstractmethod
    def connected(self):
        """
        :return: boolean
        """
        pass

    @property
    @abstractmethod
    def locked(self):
        """
        :return: boolean
        """
        pass

    @abstractmethod
    def get_interface_information(self, **kwargs):
        """
        :return: dict
        """
        pass

    def get_free_unit(self, iface):
        """
        :param iface: str
        :return: int
        """
        pass

    @abstractmethod
    def connect(self):
        """
        :return: boolean
        """
        pass

    @abstractmethod
    def disconnect(self):
        """
        :return: lxml element tree
        """
        pass

    @abstractmethod
    def get_config(self):
        """
        :return: lxml element tree
        """
        pass

    @abstractmethod
    def lock_config(self):
        """
        :return: boolean
        """
        pass

    @abstractmethod
    def unlock_config(self):
        """
        :return: boolean
        """
        pass

    @abstractmethod
    def diff(self):
        """
        :return: configuration diff
        """
        pass

    @abstractmethod
    def load_config(self, config, config_format):
        """
        :param config: string
        :param config_format: xml or text
        :return: boolean
        """
        pass

    @abstractmethod
    def rollback(self):
        """
        :return: boolean
        """
        pass

    @abstractmethod
    def commit_check(self):
        """
        :return: boolean
        """
        pass

    @abstractmethod
    def commit(self, comment=""):
        """
        :param comment: string
        :return: bool
        """
        pass

    @abstractmethod
    def create_ac(self, iface, unit, vlan_id, cust_id, circuit_id, bw_bits):
        """
        :param iface: str
        :param cust_id: str
        :param circuit_id: str
        :param vlan_id: int
        :param unit: int
        :param bw_bits: int
        :return: bool
        """
        pass

    @abstractmethod
    def delete_ac(self, iface, unit):
        """
        :param iface: string
        :param unit: int
        :return: bool
        """
        pass

    @abstractmethod
    def create_l2vpn(self, l2vpn_id, iface, unit, extra_community_name, site_id):
        """
        :param iface: string
        :param l2vpn_id
        :param unit: int
        :param site_id: int
        :param extra_community_name: string
        :return: bool
        """
        pass

    @abstractmethod
    def delete_l2vpn(self, l2vpn_id, iface, unit):
        """
        :param iface: string
        :param l2vpn_id: int
        :param unit: int
        :return: bool
        """
        pass

    @abstractmethod
    def create_trunk(self, iface, circuit_id, iface_description):
        """
        :param iface, circuit_id, iface_description: string
        :return: bool
        """
        pass

    @abstractmethod
    def create_l3vpnhub(self, l3vpn_id, max_prefixes):
        """
        :param max_prefixes: int
        :param l3vpn_id: int
        :return bool
        """
        pass

    @abstractmethod
    def delete_l3vpnhub(self, l3vpn_id):
        """
        :param l3vpn_id: int
        :return:
        """

    @abstractmethod
    def create_l3vpnce(self, l3vpn_id, inet_prefix, inet6_prefix, peer_as, iface_unit):
        """
        :param l3vpn_id: int
        :param inet_prefix: str
        :param inet6_prefix: str
        :param peer_as: int
        :param iface_unit: str
        :return bool
        """
        pass

    @abstractmethod
    def delete_l3vpnce(self, l3vpn_id, inet_prefix, inet6_prefix):
        """
        :param l3vpn_id: int
        :param inet_prefix: str
        :param inet6_prefix: str
        :param iface: str
        :param unit: int
        :param peer_as: int
        """
        pass

    @abstractmethod
    def create_evpnhub(self, evpn_id, split_horizon, designated_forwarder, route_targets, extended_communities):
        """
        :param evpn_id: int
        :param split_horizon: bool
        :param designated_forwarder: bool
        :param route_targets: str
        :param extended_communities: str
        :return: bool
        """
        pass

    @abstractmethod
    def delete_evpnhub(self, evpn_id):
        """
        :param evpn_id: int
        :return: bool
        """
        pass

    @abstractmethod
    def create_evpnce(self, evpn_id, iface_unit):
        """
        :param evpn_id: int
        :param iface_unit: str
        :return: bool
        """
        pass

    @abstractmethod
    def delete_evpnce(self, evpn_id):
        """
        :param evpn_id: int
        :return: bool
        """
        pass

