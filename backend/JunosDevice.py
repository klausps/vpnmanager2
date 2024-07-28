from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from backend.Router import Router, RouterConnectionError, RouterConfigError, RouterAuthError, RouterLockError
from jnpr.junos.exception import LockError, ConnectAuthError, ConfigLoadError, UnlockError, CommitError, RpcError

'''
from jnpr.junos import exception
from jnpr.junos.exception import ConnectError
from jnpr.junos.exception import CommitError

from jnpr.junos.exception import UnlockError
from jnpr.junos.exception import ConfigLoadError
'''

class JunosDevice(Router):
    def __init__(self, host: str, user: str, passwd: str, hwmodel: str, port=830):
        """
        :param host: str, IP address or FQDN
        :param user: str
        :param passwd: str
        :param hwmodel: str
        :param port: int
        """
        super().__init__(host, user, passwd, hwmodel, port)
        self._device = Device(host=host, user=user, passwd=passwd, port=port)
        self._cfg = Config(self._device, mode='exclusive')
        self._locked = False
        self._hwmodel = hwmodel

    @property
    def connected(self):
        """
        :return: boolean
        """
        return self._device.connected

    @property
    def locked(self):
        """
        :return: boolean
        """
        return self._locked

    def get_interface_information(self, **kwargs):
        """
        :return: dict
        """
        if not self._device.connected:
            raise RouterConnectionError
        if 'interface' in kwargs:
            return self._device.rpc.get_interface_information({'format': 'json'}, interface_name=kwargs['interface'])
        else:
            return self._device.rpc.get_interface_information({'format': 'json'})

    def get_free_unit(self, iface):
        """
        :return: int
        """
        pass

    def connect(self):
        """
        :return: boolean
        """
        try:
            return self._device.open()
        except ConnectionError as e:
            print(e)
            raise RouterConnectionError(f'Host: {self.host}')
        except ConnectAuthError as e:
            print(e)
            raise RouterAuthError(f'User: {self.user}')

    def disconnect(self):
        """
        :return: boolean
        """
        return self._device.close()

    def get_config(self):
        """
        :return: lxml element tree
        """
        self._device.rpc.get_config()

    def lock_config(self):
        """
        :return: boolean
        """
        if self._locked:
            raise RouterLockError(f'Host {self.host} already locked')
        try:
            if self._cfg.lock():
                self._locked = True
                return True
        except LockError as e:
            print(e)
            raise RouterLockError(f'Unable to lock host {self.host}')

    def unlock_config(self):
        """
        :return: boolean
        """
        if not self._locked:
            raise RouterLockError(f'Host {self.host} was not locked')
        try:
            if self._cfg.unlock():
                self._locked = False
                return True
        except LockError as e:
            print(e)
            raise RouterLockError(f'Unable to unlock host {self.host}')

    def diff(self):
        """
        :return: configuration diff
        """
        return self._cfg.diff()

    def load_config(self, config: str, config_format: str):
        """
        :param config: string
        :param config_format: xml or text
        :return: boolean
        """
        try:
            return self._cfg.load(config, format=format)
        except ConfigLoadError as e:
            print(e)
            raise RouterConfigError(f'Unable to load config on {self.host}')

    def rollback(self):
        """
        :return: boolean
        """
        try:
            return self._cfg.rollback()
        except UnlockError as e:
            print(e)
            raise RouterLockError(f'Unable to rollback config on {self.host}')

    def commit_check(self):
        try:
            return self._cfg.commit_check()
        except CommitError as e:
            print(e)
            raise RouterConfigError(f'Unable to check config on {self.host}')
        except RpcError as e:
            print(e)
            raise RouterConfigError(f'Unable to check config on {self.host}')

    def commit(self, **kwargs):
        """
        :param kwargs:
        :return:
        """
        try:
            if 'comment' in kwargs:
                return self._cfg.commit(comment=kwargs['comment'], )
            return self._cfg.commit(ignore_warning=True)
        except CommitError as e:
            print(e)
            raise RouterConfigError(f'Unable to commit config on {self.host}')

    def create_ac(self, iface, unit, vlan_id, cust_id, circuit_id,bw_bits):
        pass

    def delete_ac(self, iface, unit):
        pass

    def create_l2vpn(self, l2vpn_id, iface, unit, extra_community_name, site_id):
        pass

    def delete_l2vpn(self, l2vpn_id, iface, unit):
        pass

    def create_trunk(self, iface, circuit_id, iface_description):
        pass

    def create_l3vpnhub(self, l3vpn_id, max_prefixes):
        pass