import yaml
import json
from collections import OrderedDict
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, UniqueConstraint
from sqlalchemy.orm import declared_attr, aliased


db = SQLAlchemy()

class BaseModel(db.Model):
    __abstract__ = True

    @declared_attr
    def id(cls):
        return db.Column(db.Integer, primary_key=True, autoincrement=True)

    creation_date = db.Column(db.TIMESTAMP, server_default=func.current_timestamp())
    last_modified = db.Column(db.TIMESTAMP, server_default=func.current_timestamp(), onupdate=func.current_timestamp())

    def to_yaml(self, tree_view=False):
        def ordered_dict_representer(dumper, data):
            return dumper.represent_dict(data.items())

        yaml.add_representer(OrderedDict, ordered_dict_representer)
        return yaml.dump(self.to_dict(tree_view), default_flow_style=False, sort_keys=False, explicit_start=True, allow_unicode=True)

    def to_json(self, tree_view=False):
        return json.dumps(self.to_dict(tree_view), indent=4)


class Site(BaseModel):
    __tablename__ = 'sites'
    tag = db.Column(db.String(8), unique=True, nullable=False)
    name = db.Column(db.String(32))
    address = db.Column(db.String(128))
    city = db.Column(db.String(32), nullable=False)
    state = db.Column(db.String(2), nullable=False)
    country = db.Column(db.String(2), nullable=False, default='BR')
    zip = db.Column(db.String(10))
    latitude = db.Column(db.String(15), nullable=False)
    longitude = db.Column(db.String(15), nullable=False)

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('tag', self.tag),
            ('name', self.name),
            ('address', self.address),
            ('city', self.city),
            ('state', self.state),
            ('country', self.country),
            ('zip', self.zip),
            ('latitude', self.latitude),
            ('longitude', self.longitude),
            ('creation_date', self.creation_date.isoformat() if self.creation_date else None),
            ('last_modified', self.last_modified.isoformat() if self.last_modified else None),
        ])
        if tree_view:
            nodes = Node.query.filter_by(site_id=self.id).all()
            data['Nodes'] = [node.to_dict(tree_view=tree_view) for node in nodes]
        return data


class NODEType(BaseModel):
    __tablename__ = 'nodetype'
    name = db.Column(db.Enum('PEVPN', 'PEIP', 'P', name='nodetype'), nullable=False)

    node = db.relationship("Node", backref='nodetype')


class HWType(BaseModel):
    __tablename__ = 'hwtype'
    model = db.Column(db.String(16), unique=True, nullable=False)
    vendor = db.Column(db.String(16), unique=False, nullable=False)

    node = db.relationship("Node", backref='hwtypes')


class Node(BaseModel):
    __tablename__ = 'node'

    hwtype_id = db.Column(db.Integer, db.ForeignKey('hwtype.id'), nullable=False)
    nodetype_id = db.Column(db.Integer, db.ForeignKey('nodetype.id'), nullable=False)
    name = db.Column(db.String(16), nullable=False)
    ipaddr = db.Column(db.String(15), unique=True, nullable=False)
    snmp_community = db.Column(db.String(16), nullable=False)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.id'), nullable=False)

    site = db.relationship("Site", backref='nodes')

    __table_args__ = (
        UniqueConstraint('name', 'site_id', name='node_idx'),
    )

    def to_dict(self, tree_view=False):
        nodetype = NODEType.query.get(self.nodetype_id)
        hwtype = HWType.query.get(self.hwtype_id)
        site = Site.query.get(self.site_id)
        data = OrderedDict([
            ('id', self.id),
            ('hwtype_model', hwtype.model),
            ('hwtype_vendor', hwtype.vendor),
            ('nodetype', nodetype.name),
            ('name', self.name),
            ('ipaddr', self.ipaddr),
            ('snmp_community', self.snmp_community),
            ('site_id', self.site_id),
            ('site_tag', site.tag),
            ('hwtype_model', hwtype.model),
            ('hwtype_vendor', hwtype.vendor),
            ('creation_date', self.creation_date.isoformat() if self.creation_date else None),
            ('last_modified', self.last_modified.isoformat() if self.last_modified else None),
        ])
        if tree_view:

            if self.nodetype.name == 'PEVPN':
                trunks = Trunk.query.filter_by(node_id=self.id).all()
                data['Trunks'] = [trunk.to_dict(tree_view=tree_view) for trunk in trunks]
            elif self.nodetype.name == 'PEIP':
                instances = Instance.query.filter_by(node_id=self.id).all()
                data['Instances'] = [instance.to_dict(tree_view=tree_view) for instance in instances]

        return data


class Trunk(BaseModel):
    __tablename__ = 'trunk'

    # Reference to Node
    node_id = db.Column(db.Integer, db.ForeignKey('node.id'), nullable=False)
    circuit_id = db.Column(db.String(64), unique=True, nullable=False)
    iface = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(64), nullable=False)

    node = db.relationship("Node", backref='trunks')
    __table_args__ = (
        UniqueConstraint('node_id', 'iface', name='trunk_idx'),
    )

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('node_id', self.node_id),
            ('circuit_id', self.circuit_id),
            ('iface', self.iface),
            ('description', self.description),
            ('creation_date', self.creation_date.isoformat() if self.creation_date else None),
            ('last_modified', self.last_modified.isoformat() if self.last_modified else None),
        ])
        if tree_view:
            l2vpns = self.get_l2vpns()
            data['L2VPNs'] = [l2vpn.to_dict() for l2vpn in l2vpns]
        return data

    def get_l2vpns(self):
        l2vpns = set()
        for ac in self.acs:
            for l2vpn in ac.l2vpn_ac1:
                l2vpns.add(l2vpn)
            for l2vpn in ac.l2vpn_ac2:
                l2vpns.add(l2vpn)
        return list(l2vpns)


class AC(BaseModel):
    __tablename__ = 'ac'

    # Reference to Trunk
    trunk_id = db.Column(db.Integer, db.ForeignKey('trunk.id'), nullable=False)

    vlan_id = db.Column(db.Integer, nullable=False)
    unit = db.Column(db.Integer, nullable=False)

    # Relationship with Trunk
    trunk = db.relationship("Trunk", backref='acs')
    __table_args__ = (
        UniqueConstraint('trunk_id', 'unit', 'vlan_id', name='ac_idx'),
    )

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('vlan_id', self.vlan_id),
            ('unit', self.unit),
            ('creation_date', self.creation_date.isoformat() if self.creation_date else None),
            ('last_modified', self.last_modified.isoformat() if self.last_modified else None),
        ])
        return data

class L2VPN(BaseModel):
    __tablename__ = 'l2vpn'

    # References to ACs
    ac1_id = db.Column(db.Integer, db.ForeignKey('ac.id'), nullable=False)
    ac2_id = db.Column(db.Integer, db.ForeignKey('ac.id'), nullable=False)
    circuit_id = db.Column(db.String(64), nullable=False)
    cust_id = db.Column(db.String(64), nullable=False)
    bw_bits = db.Column(db.BigInteger, nullable=False)
    sync = db.Column(db.Boolean, nullable=False, default=False)
    protected = db.Column(db.Boolean, nullable=False, default=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)

    # Relationships with ACs
    ac1 = db.relationship("AC", foreign_keys=[ac1_id], backref='l2vpn_ac1')
    ac2 = db.relationship("AC", foreign_keys=[ac2_id], backref='l2vpn_ac2')
    task = db.relationship("Task", foreign_keys=[task_id], backref='l2vpn_task')

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('circuit_id', self.circuit_id),
            ('cust_id', self.cust_id),
            ('bw_bits', self.bw_bits),
            ('sync', self.sync),
            ('protected', self.protected),
            ('creation_date', self.creation_date.isoformat() if self.creation_date else None),
            ('last_modified', self.last_modified.isoformat() if self.last_modified else None),
        ])
        if tree_view:
            data['Trunk1'] = OrderedDict([
                ('node_name', self.ac1.trunk.node.name),
                ('node_site', self.ac1.trunk.node.site.tag),
                ('circuit_id', self.ac1.trunk.circuit_id),
                ('ac1_vlan', self.ac1.vlan_id),
                ('iface', self.ac1.trunk.iface),
            ])
            data['Trunk2'] = OrderedDict([
                ('node_name', self.ac2.trunk.node.name),
                ('node_site', self.ac2.trunk.node.site.tag),
                ('circuit_id', self.ac2.trunk.circuit_id),
                ('ac2_vlan', self.ac2.vlan_id),
                ('iface', self.ac2.trunk.iface),
            ])
        return data

    def create_l2vpn(self, data):
        pass


class L3VPN(BaseModel):
    __tablename__ = 'l3vpn'

    max_prefixes = db.Column(db.SmallInteger, nullable=False)
    circuit_id = db.Column(db.String(64), unique=True, nullable=False)
    cust_id = db.Column(db.String(64), nullable=False)

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('circuit_id', self.circuit_id),
            ('cust_id', self.cust_id),
            ('max_prefixes', self.max_prefixes),
            ('creation_date', self.creation_date.isoformat() if self.creation_date else None),
            ('last_modified', self.last_modified.isoformat() if self.last_modified else None),
        ])
        if tree_view:
            hubs = L3VPNHub.query.filter_by(l3vpn_id=self.id).all()
            data['Hubs'] = [hub.to_dict(tree_view=tree_view) for hub in hubs]
        return data

class L3VPNHub(BaseModel):
    __tablename__ = 'l3vpn_hub'

    # Reference to L3VPN
    l3vpn_id = db.Column(db.Integer, db.ForeignKey('l3vpn.id'), nullable=False)
    # Reference to Node
    node_id = db.Column(db.Integer, db.ForeignKey('node.id'), nullable=False)

    # Relationships with L3VPN and Node
    l3vpn = db.relationship("L3VPN", foreign_keys=[l3vpn_id], backref='l3vpn_hubs')
    node = db.relationship("Node", foreign_keys=[node_id], backref='l3vpn_hubs')
    __table_args__ = (
        UniqueConstraint('node_id', 'l3vpn_id', name='l3vpnhub_idx'),
    )

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('node_name', self.node.name),
            ('node_site', self.node.site.tag),
            ('node_id', self.node.id)
            ])

        if tree_view:
            ces = L3VPNCE.query.filter_by(hub_id=self.id).all()
            data['CEs'] = [ce.to_dict(tree_view=tree_view) for ce in ces]
        return data

class L3VPNCE(BaseModel):
    __tablename__ = 'l3vpn_ce'

    # Reference to L3VPNHub
    hub_id = db.Column(db.Integer, db.ForeignKey('l3vpn_hub.id'), nullable=False)
    # Reference to Trunk
    trunk_id = db.Column(db.Integer, db.ForeignKey('trunk.id'), nullable=False)
    # Reference to AC
    ac_id = db.Column(db.Integer, db.ForeignKey('ac.id'), nullable=False)
    circuit_id = db.Column(db.String(64), unique=True, nullable=False)
    inet_prefix = db.Column(db.String(18), nullable=False)
    inet6_prefix = db.Column(db.String(43), nullable=False)
    bw_bits = db.Column(db.BigInteger, nullable=False)
    peer_as = db.Column(db.Integer, nullable=False)

    # Relationships with L3VPNHub, Trunk, and AC
    hub = db.relationship("L3VPNHub", foreign_keys=[hub_id], backref='l3vpn_ces')
    trunk = db.relationship("Trunk", foreign_keys=[trunk_id], backref='l3vpn_ces')
    ac = db.relationship("AC", foreign_keys=[ac_id], backref='l3vpn_ac')

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('circuit_id', self.circuit_id),
            ('inet_prefix', self.inet_prefix),
            ('inet6_prefix', self.inet6_prefix),
            ('bw_bits', self.bw_bits)
            ])
        if tree_view:
            ac = AC.query.filter_by(id=self.ac_id).first()
            data['AC'] = OrderedDict([
                ('trunk_circuit_id', ac.trunk.circuit_id),
                ('trunk_iface', ac.trunk.iface),
                ('ac_id', ac.id),
                ('ac_unit', ac.unit),
                ('ac_vlan', ac.vlan_id),
            ])
        return data
    __table_args__ = (
        UniqueConstraint('hub_id', 'ac_id', name='l3vpn_ce_idx'),
    )


class EVPN(BaseModel):
    __tablename__ = 'evpn'

    mac_address_table_limit = db.Column(db.SmallInteger, nullable=False)
    circuit_id = db.Column(db.String(64), unique=True, nullable=False)
    cust_id = db.Column(db.String(64), nullable=False)

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('circuit_id', self.circuit_id),
            ('cust_id', self.cust_id),
            ('mac_address_table_limit', self.mac_address_table_limit),
            ('creation_date', self.creation_date.isoformat() if self.creation_date else None),
            ('last_modified', self.last_modified.isoformat() if self.last_modified else None),
        ])
        if tree_view:
            hubs = EVPNHub.query.filter_by(evpn_id=self.id).all()
            data['Hubs'] = [hub.to_dict(tree_view=tree_view) for hub in hubs]
        return data


class EVPNHub(BaseModel):
    __tablename__ = 'evpn_hub'

    # Reference to EVPN
    evpn_id = db.Column(db.Integer, db.ForeignKey('evpn.id'), nullable=False)
    # Reference to Node
    node_id = db.Column(db.Integer, db.ForeignKey('node.id'), nullable=False)

    split_horizon = db.Column(db.Boolean, nullable=False)
    designated_forwarder = db.Column(db.Boolean, nullable=False)
    route_targets = db.Column(db.String(256))
    extended_communities = db.Column(db.String(256))

    # Relationships with EVPN and Node
    evpn = db.relationship("EVPN", foreign_keys=[evpn_id], backref='evpn_hubs')
    node = db.relationship("Node", foreign_keys=[node_id], backref='evpn_hubs')
    __table_args__ = (
        UniqueConstraint('node_id', 'evpn_id', name='evpnhub_idx'),
    )

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('split_horizon', self.split_horizon),
            ('designated_forwarder', self.designated_forwarder),
            ('route_targets', self.route_targets),
            ('extended_communities', self.extended_communities),
            ('node_name', self.node.name),
            ('node_site', self.node.site.tag),
            ('node_id', self.node.id)
        ])

        if tree_view:
            ces = EVPNCE.query.filter_by(hub_id=self.id).all()
            data['CEs'] = [ce.to_dict(tree_view=tree_view) for ce in ces]
        return data


class EVPNCE(BaseModel):
    __tablename__ = 'evpn_ce'

    # Reference to EVPNHub
    hub_id = db.Column(db.Integer, db.ForeignKey('evpn_hub.id'), nullable=False)
    # Reference to AC
    ac_id = db.Column(db.Integer, db.ForeignKey('ac.id'), nullable=False)

    circuit_id = db.Column(db.String(64), unique=True, nullable=False)

    # Relationships with EVPNHub and AC
    hub = db.relationship("EVPNHub", foreign_keys=[hub_id], backref='evpn_ces')
    ac = db.relationship("AC", foreign_keys=[ac_id], backref='evpn_ac')
    __table_args__ = (
        UniqueConstraint('hub_id', 'ac_id', name='evpn_ce_idx'),
    )

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('circuit_id', self.circuit_id)
        ])
        if tree_view:
            ac = AC.query.filter_by(id=self.ac_id).first()
            data['AC'] = OrderedDict([
                ('trunk_circuit_id', ac.trunk.circuit_id),
                ('trunk_iface', ac.trunk.iface),
                ('ac_id', ac.id),
                ('ac_unit', ac.unit),
                ('ac_vlan', ac.vlan_id),
            ])
        return data

class RT(BaseModel):
    __tablename__ = 'rt'
    description = db.Column(db.String(45), nullable=False)
    target = db.Column(db.String(45), nullable=False)

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('description', self.description),
            ('target', self.target),
            ('creation_date', self.creation_date.isoformat() if self.creation_date else None),
            ('last_modified', self.last_modified.isoformat() if self.last_modified else None),
        ])
        return data

class Instance(BaseModel):
    __tablename__ = 'instance'
    name = db.Column(db.String(64), nullable=False)
    node_id = db.Column(db.Integer, db.ForeignKey('node.id'), nullable=False)
    type = db.Column(db.Enum('transit', 'pni', 'peering', 'cdn', 'customer', 'core', name='instance_type'), default=None)
    rt_id = db.Column(db.Integer, db.ForeignKey('rt.id'), nullable=False)

    node = db.relationship("Node", backref='instances')
    rt = db.relationship("RT", backref='instances')

    __table_args__ = (
        UniqueConstraint('node_id', 'name', name='instance_fk1_idx'),
    )

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('name', self.name),
            ('node_id', self.node_id),
            ('type', self.type),
            ('rt_id', self.rt_id),
            ('rt_description', self.rt.description),
            ('creation_date', self.creation_date.isoformat() if self.creation_date else None),
            ('last_modified', self.last_modified.isoformat() if self.last_modified else None),
        ])
        if tree_view:
            bgpgroups = BGPGroup.query.filter_by(instance_id=self.id).all()
            data['BGPGroups'] = [bgpgroup.to_dict(tree_view=tree_view) for bgpgroup in bgpgroups]
        return data


class BGPGroup(BaseModel):
    __tablename__ = 'bgpgroup'
    name = db.Column(db.String(45), nullable=True, default=None)
    peeras = db.Column(db.Integer, nullable=False, default='none')
    instance_id = db.Column(db.Integer, db.ForeignKey('instance.id'), nullable=False)

    instance = db.relationship("Instance", backref='bgpgroups')

    __table_args__ = (
        UniqueConstraint('name', 'instance_id', name='bgpgroup_fk1_idx'),
    )

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('name', self.name),
            ('peeras', self.peeras),
            ('instance_id', self.instance_id),
            ('creation_date', self.creation_date.isoformat() if self.creation_date else None),
            ('last_modified', self.last_modified.isoformat() if self.last_modified else None),
        ])
        if tree_view:
            neighbors = Neighbor.query.filter_by(bgpgroup_id=self.id).all()
            data['Neighbors'] = [neighbor.to_dict(tree_view=tree_view) for neighbor in neighbors]
        return data


class Neighbor(BaseModel):
    __tablename__ = 'neighbor'
    ipaddr = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(16), nullable=True, default=None)
    bgpgroup_id = db.Column(db.Integer, db.ForeignKey('bgpgroup.id'), nullable=False)
    peeras = db.Column(db.Integer, nullable=True, default=0)
    export_policy = db.Column(db.String(16), nullable=True, default='none')
    bgpgroup = db.relationship("BGPGroup", backref='neighbors')

    __table_args__ = (
        UniqueConstraint('ipaddr', 'bgpgroup_id', name='neighbor_fk1_idx'),
    )

    def to_dict(self, tree_view=False):
        data = OrderedDict([
            ('id', self.id),
            ('ipaddr', self.ipaddr),
            ('description', self.description),
            ('bgpgroup_id', self.bgpgroup_id),
            ('bgpgroup_name', self.bgpgroup.name),
            ('peeras', self.peeras),
            ('export_policy', self.export_policy),
            ('creation_date', self.creation_date.isoformat() if self.creation_date else None),
            ('last_modified', self.last_modified.isoformat() if self.last_modified else None),
        ])
        return data

class Task(BaseModel):
    __tablename__ = 'task'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_type = db.Column(db.String(64))  # l2vpn, node, ac, etc.
    operation_type = db.Column(db.String(10))  # add, update, delete
    input_data = db.Column(db.Text(10000000))
    logging_data = db.Column(db.Text(10000000))
    status = db.Column(db.Integer, nullable=False)  # 0 = waiting sync, 1 = sync done, 2 = error

class User(BaseModel):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255))
    password = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, unique=False, default=True)
    is_authenticated = db.Column(db.Boolean, unique=False, default=False)
