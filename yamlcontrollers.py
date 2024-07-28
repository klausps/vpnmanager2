from models import *
from backend import DummyDevice
from backend import RouterConnectionError, RouterConfigError, RouterLockError, RouterAuthError
from config import router_user, router_password
from sqlalchemy.exc import SQLAlchemyError
from app import app, db


def process_operations(file_path):
    try:
        with open(file_path, 'r') as file:
            operations = yaml.safe_load(file)
            if not operations:
                return
            for operation in operations:
                execute_operation(operation)
    except (yaml.YAMLError, FileNotFoundError) as e:
        print(f"Error loading operations file: {e}")


def execute_operation(operation):
    op_type = operation.get('operation')
    handler = {
        'create': handle_create,
        'read': handle_read,
        'update': handle_update,
        'delete': handle_delete
    }.get(op_type)
    if handler:
        handler(operation)
    else:
        print(f"Unknown operation type: {op_type}")


def handle_create(operation):
    data = operation.get('data')
    create_func = {
        'site': create_site,
        'node': create_node,
        'trunk': create_trunk,
        'l2vpn': create_l2vpn,
        'l3vpn': create_l3vpn,
        'l3vpnhub': create_l3vpnhub,
        'l3vpnce': create_l3vpnce,
        'evpn': create_evpn,
        'evpnhub': create_evpnhub,
        'evpnce': create_evpnce,
        'rt': create_rt,
        'instance': create_instance,
        'bgpgroup': create_bgpgroup,
        'neighbor': create_neighbor
    }.get(operation.get('type'))
    if create_func and data:
        create_func(data)
    else:
        print("Create operation missing data or unknown type")


def handle_read(operation):
    filter_data = operation.get('filter')
    tree_view = operation.get('tree_view', False)
    read_func = {
        'site': read_site,
        'node': read_node,
        'trunk': read_trunk,
        'l2vpn': read_l2vpn,
        'l3vpn': read_l3vpn,
        'l3vpnhub': read_l3vpnhub,
        'l3vpnce': read_l3vpnce,
        'evpn': read_evpn,
        'evpnhub': read_evpnhub,
        'evpnce': read_evpnce,
        'rt': read_rt,
        'instance': read_instance,
        'bgpgroup': read_bgpgroup,
        'neighbor': read_neighbor
    }.get(operation.get('type'))
    if read_func:
        read_func(filter_data, tree_view=tree_view)
    else:
        print("Unknown read type")


def handle_update(operation):
    filter_data = operation.get('filter')
    data = operation.get('data')
    update_func = {
        'site': update_site,
        'node': update_node,
        'trunk': update_trunk,
        'l2vpn': update_l2vpn,
        'l3vpn': update_l3vpn,
        'l3vpnhub': update_l3vpnhub,
        'l3vpnce': update_l3vpnce,
        'evpn': update_evpn,
        'evpnhub': update_evpnhub,
        'evpnce': update_evpnce,
        'rt': update_rt,
        'instance': update_instance,
        'bgpgroup': update_bgpgroup,
        'neighbor': update_neighbor
    }.get(operation.get('type'))
    if update_func and filter_data and data:
        update_func(filter_data, data)
    else:
        print("Update operation missing filter, data, or unknown type")


def handle_delete(operation):
    filter_data = operation.get('filter')
    delete_func = {
        'site': delete_site,
        'node': delete_node,
        'trunk': delete_trunk,
        'l2vpn': delete_l2vpn,
        'l3vpn': delete_l3vpn,
        'l3vpnhub': delete_l3vpnhub,
        'l3vpnce': delete_l3vpnce,
        'evpn': delete_evpn,
        'evpnhub': delete_evpnhub,
        'evpnce': delete_evpnce,
        'rt': delete_rt,
        'instance': delete_instance,
        'bgpgroup': delete_bgpgroup,
        'neighbor': delete_neighbor
    }.get(operation.get('type'))
    if delete_func and filter_data:
        delete_func(filter_data)
    else:
        print("Delete operation missing filter or unknown type")


def with_app_context(f):
    def wrapped(*args, **kwargs):
        with app.app_context():
            return f(*args, **kwargs)

    return wrapped

def connect_and_lock(ipaddr, vendor, model):
    """
    :param ipaddr: str
    :param vendor: str
    :param model: str
    :return: Router object
    """
    device = None
    if vendor == 'Juniper':
        try:
            device = DummyDevice(host=ipaddr, user=router_user, passwd=router_password, hwmodel=model)
            device.connect()
            device.lock_config()
        except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
            print(f"Error connecting or locking the router configuration {ipaddr}: {e}")
    return device

def commit_and_disconnect(device, rollback):
    """
    :param device: object
    :param rollback: bool
    :return: bool
    """
    if not rollback:
        device.commit()
        device.unlock_config()
        device.disconnect()
    else:
        device.rollback()
        device.unlock_config()
        device.disconnect()

def create_task(operation_type, task_type, data):
    try:
        new_task = Task(
            user_id=1,
            operation_type=operation_type,
            task_type=task_type,
            input_data=str(data),
            status=0
        )
        db.session.add(new_task)
        db.session.commit()
        return new_task.id
    except Exception as e:
        db.session.rollback()
        print(f'Error creating task: {e}')
        return None


@with_app_context
def create_site(data):
    try:
        new_site = Site(**data)
        db.session.add(new_site)
        db.session.commit()
        print(f"Created site: {new_site.tag}")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error creating site: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()


@with_app_context
def read_site(filter_data=None, tree_view=False):
    try:
        if filter_data is not None:
            print(f"Filter data provided: {filter_data}")
            sites = Site.query.filter_by(**filter_data).all()
        else:
            sites = Site.query.all()
        if sites:
            for site in sites:
                print(site.to_yaml(tree_view))
        else:
            print("Message: No site found.")
    except Exception as e:
        print(f"Unexpected error: {e}")


@with_app_context
def update_site(filter_data, update_data):
    print(f"Updating site with filter: {filter_data}, data: {update_data}")
    try:
        tag = filter_data['tag']
        site = Site.query.filter_by(tag=tag).first()
        if site:
            for key, value in update_data.items():
                setattr(site, key, value)
            db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error updating site: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()


@with_app_context
def delete_site(filter_data):
    try:
        tag = filter_data['tag']
        site = Site.query.filter_by(tag=tag).first()
        if site:
            db.session.delete(site)
            db.session.commit()
            print(f"Deleting site with filter: {filter_data}")
        else:
            print("Site not found.")
    except Exception as e:
        print(f"Unexpected error: {e}")


@with_app_context
def create_node(data):
    try:
        site_tag = data['site_tag']
        hwtype_model = data['hwtype_model']
        nodetype_name = data['nodetype_name']
        site = Site.query.filter_by(tag=site_tag).first()
        hwtype = HWType.query.filter_by(model=hwtype_model).first()
        nodetype = NODEType.query.filter_by(name=nodetype_name).first()

        if not site:
            print(f"Site not found with tag: {site_tag}")
            return

        new_node = Node(
            hwtype_id=hwtype.id,
            nodetype_id=nodetype.id,
            name=data['name'],
            ipaddr=data['ipaddr'],
            snmp_community=data.get('snmp_community'),
            site_id=site.id
        )
        db.session.add(new_node)
        db.session.commit()
        print(f"Created Node: {new_node.name}")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error creating Node: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()


@with_app_context
def read_node(filter_data=None, tree_view=False):
    print(filter_data)
    try:
        if 'name' and 'site_tag' in filter_data:
            site_tag = filter_data['site_tag']
            name = filter_data['name']
            node = Node.query.join(Site).filter(Node.name == name, Site.tag == site_tag).first()
            print(node.to_yaml(tree_view))
        else:
            nodes = Node.query.all()
            if nodes:
                for node in nodes:
                    print(node.to_yaml(tree_view))
            else:
                print("Message: No Node found.")
    except Exception as e:
        print(f"Unexpected error: {e}")


@with_app_context
def update_node(filter_data, update_data):
    print(f"Updating Node with filter: {filter_data}, data: {update_data}")
    if 'name' and 'site_tag' in filter_data:
        name = filter_data['name']
        site_tag = filter_data['site_tag']
        try:
            node = Node.query.join(Site).filter(Node.name == name, Site.tag == site_tag).first()
            if node:
                if 'site_tag' in update_data and update_data['site_tag'] != filter_data['site_tag']:
                    new_site_tag = update_data['site_tag']
                    site = Site.query.filter_by(tag=new_site_tag).first()
                    node.site_id = site.id
                if 'hwtype_model' in update_data:
                    new_hwtype_model = update_data['hwtype_model']
                    new_hwtype = HWType.query.filter_by(model=new_hwtype_model).first()
                    print()
                    node.hwtype_id = new_hwtype.id
                for key, value in update_data.items():
                    if key != 'site_tag':
                        setattr(node, key, value)
                db.session.commit()
                print("Node updated successfully.")
                print(node.to_yaml())
            else:
                print("Node not found")
        except SQLAlchemyError as e:
            db.session.rollback()
            print(f"Error updating Node: {e}")
        except Exception as e:
            db.session.rollback()
            print(f"Unexpected error: {e}")
        finally:
            db.session.close()
    else:
        print("Node name and/or site_tag not specified.")


@with_app_context
def delete_node(filter_data):
    if 'name' and 'site_tag' in filter_data:
        try:
            name = filter_data['name']
            site_tag = filter_data['site_tag']
            node = Node.query.join(Site).filter(Node.name == name, Site.tag == site_tag).first()
            if node:
                db.session.delete(node)
                db.session.commit()
                print(f"Deleted Node with filter: {filter_data}")
            else:
                print("Node not found.")
        except Exception as e:
            print(f"Unexpected error: {e}")
    else:
        print("Node name and/or site_tag not specified.")


@with_app_context
def create_trunk(data):
    try:
        # Creating task
        task_id = create_task(operation_type='create', task_type='trunk', data=data)
        node_name = data['node_name']
        site_tag = data['site_tag']
        node = Node.query.join(Site).filter(Node.name == node_name, Site.tag == site_tag).first()
        if not node:
            print(f"Node not found with name: {node_name} and site tag: {site_tag}")
            return

        new_trunk = Trunk(
            node_id=node.id,
            circuit_id=data['circuit_id'],
            iface=data['iface'],
            description=data['description']
        )

        print(node.hwtypes.vendor)

        # Router related test code block
        device = connect_and_lock(node.ipaddr, node.hwtypes.vendor, node.hwtypes.model)
        device.create_trunk(iface=new_trunk.iface, circuit_id=new_trunk.circuit_id,
                            iface_description=new_trunk.description)
        device.commit_check()
        device.diff()
        db.session.add(new_trunk)
        # End of router related code block test code
        if input("Type YES to confirm: ") == "YES":
            task = Task.query.filter_by(id=task_id).first()
            task.status = 1
            db.session.commit()
            commit_and_disconnect(device=device, rollback=False)
            print(f"Created Trunk: {new_trunk.circuit_id}")
        else:
            db.session.rollback()
            commit_and_disconnect(device=device, rollback=True)
    except SQLAlchemyError as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Error creating Trunk on database. Error: {e}")
    except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
        db.session.rollback()
        print(f"Error creating Trunk on router. Error: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()


@with_app_context
def read_trunk(filter_data=None, tree_view=False):
    print(filter_data)
    try:
        if 'circuit_id' in filter_data:
            circuit_id = filter_data['circuit_id']
            trunk = Trunk.query.filter_by(circuit_id=circuit_id).first()
            if trunk:
                print(trunk.to_yaml(tree_view))
            else:
                print("Message: Trunk not found.")
        else:
            trunks = Trunk.query.all()
            if trunks:
                for trunk in trunks:
                    print(trunk.to_yaml(tree_view))
            else:
                print("Message: No Trunks found.")
    except Exception as e:
        print(f"Unexpected error: {e}")


@with_app_context
def update_trunk(filter_data, update_data):
    print(f"Updating Trunk with filter: {filter_data}, data: {update_data}")
    if 'circuit_id' in filter_data:
        circuit_id = filter_data['circuit_id']
        try:

            trunk = Trunk.query.filter_by(circuit_id=circuit_id).first()
            if trunk:
                # Creating task
                task_id = create_task(operation_type='update', task_type='trunk',
                                      data={'filter': filter_data, 'update_data': update_data})

                # Router related test code block
                device = connect_and_lock(trunk.node.ipaddr, trunk.node.hwtypes.vendor, trunk.node.hwtypes.model)
                device.create_trunk(iface=trunk.iface, circuit_id=trunk.circuit_id, iface_description=trunk.description)
                device.commit_check()
                device.diff()
                # End of router related code block test code

                for key, value in update_data.items():
                    setattr(trunk, key, value)
                task = Task.query.filter_by(id=task_id).first()
                task.status = 1
                db.session.commit()
                device.commit()
                device.unlock_config()
                device.disconnect()
                print("Trunk updated successfully.")
                print(trunk.to_yaml())
            else:
                print("Trunk not found")
        except SQLAlchemyError as e:
            db.session.rollback()
            print(f"Error updating Trunk: {e}")
        except Exception as e:
            db.session.rollback()
            print(f"Unexpected error: {e}")
        finally:
            db.session.close()
    else:
        print("Trunk circuit_id not specified.")


@with_app_context
def delete_trunk(filter_data):
    if 'circuit_id' in filter_data:
        try:
            circuit_id = filter_data['circuit_id']
            trunk = Trunk.query.filter_by(circuit_id=circuit_id).first()
            if trunk:
                # Creating task
                task_id = create_task(operation_type='delete', task_type='trunk', data=filter_data)
                db.session.delete(trunk)
                print(f"Deleted Trunk with filter: {filter_data}")
                task = Task.query.filter_by(id=task_id).first()
                db.session.commit()
                setattr(task, 'status', 1)
            else:
                print("Trunk not found.")
        except Exception as e:
            print(f"Unexpected error: {e}")
    else:
        print("Trunk circuit_id not specified.")


@with_app_context
def create_l2vpn(data):
    # create an object from the router
    try:
        task_id = create_task(operation_type='create', task_type='l2vpn', data=data)
        new_trunk1_circuit_id = data['trunk1_circuit_id']
        new_trunk2_circuit_id = data['trunk2_circuit_id']
        if not new_trunk2_circuit_id or not new_trunk1_circuit_id:
            print(
                f"One or both trunks not found: trunk1_circuit_id={new_trunk1_circuit_id}, trunk2_circuit_id={new_trunk2_circuit_id}")
            return
        trunk1 = Trunk.query.filter_by(circuit_id=new_trunk1_circuit_id).first()
        trunk2 = Trunk.query.filter_by(circuit_id=new_trunk2_circuit_id).first()

        device1 = connect_and_lock(trunk1.node.ipaddr, trunk1.node.hwtypes.vendor, trunk1.node.hwtypes.model)
        device2 = connect_and_lock(trunk2.node.ipaddr, trunk2.node.hwtypes.vendor, trunk2.node.hwtypes.model)

        new_ac1 = AC(
            trunk_id=trunk1.id,
            vlan_id=data.get('vlan_trunk1'),
            unit=device1.get_free_unit(trunk1.iface)
        )

        new_ac2 = AC(
            trunk_id=trunk2.id,
            vlan_id=data.get('vlan_trunk2'),
            unit=device1.get_free_unit(trunk1.iface)
        )

        db.session.add(new_ac1)
        db.session.add(new_ac2)
        db.session.flush()
        new_l2vpn = L2VPN(
            ac1_id=new_ac1.id,
            ac2_id=new_ac2.id,
            circuit_id=data['circuit_id'],
            cust_id=data['cust_id'],
            bw_bits=data['bw_bits'],
            sync=data.get('sync', False),
            protected=data.get('protected', False),
            task_id=task_id
        )
        db.session.add(new_l2vpn)
        db.session.flush()

        # Start of router related code block test code
        device1.create_ac(iface=trunk1.iface, unit=new_ac1.unit, vlan_id=new_ac1.vlan_id, cust_id=new_l2vpn.cust_id,
                          circuit_id=new_l2vpn.circuit_id, bw_bits=new_l2vpn.bw_bits)
        device1.create_l2vpn(l2vpn_id=new_l2vpn.id, iface=trunk1.iface, unit=new_ac1.unit,
                             extra_community_name="cm-l2vpn-prot" if new_l2vpn.protected == 1 else "cm-l2vpn-unprot",
                             site_id=1)
        device1.create_ac(iface=trunk2.iface, unit=new_ac2.unit, vlan_id=new_ac2.vlan_id, cust_id=new_l2vpn.cust_id,
                          circuit_id=new_l2vpn.circuit_id, bw_bits=new_l2vpn.bw_bits)
        device2.create_l2vpn(l2vpn_id=new_l2vpn.id, iface=trunk2.iface, unit=new_ac2.unit,
                             extra_community_name="cm-l2vpn-prot" if new_l2vpn.protected == 1 else "cm-l2vpn-unprot",
                             site_id=2)
        device1.commit_check()
        device2.commit_check()
        device1.diff()
        device2.diff()
        task = Task.query.filter_by(id=task_id).first()
        # End of router related code block test code
        if input("Type YES to confirm: ") == "YES":
            task.status = 1
            db.session.commit()
            commit_and_disconnect(device=device1, rollback=False)
            commit_and_disconnect(device=device2, rollback=False)
            print(f"Created L2VPN: {new_l2vpn.circuit_id}")
        else:
            commit_and_disconnect(device=device1, rollback=True)
            commit_and_disconnect(device=device2, rollback=True)
            db.session.rollback()
            task.status = 1
            db.session.commit()

    except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
        db.session.rollback()
        print(f"Error creating L2VPN: {e}")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error creating L2VPN: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()


@with_app_context
def read_l2vpn(filter_data=None, tree_view=False):
    try:
        query = L2VPN.query
        if isinstance(filter_data, dict) and 'id' in filter_data:
            query = query.filter_by(id=filter_data['id'])
        l2vpns = query.all()
        if l2vpns:
            for l2vpn in l2vpns:
                print(l2vpn.to_yaml(tree_view))
        else:
            print("Message: L2VPN not found.")
    except Exception as e:
        print(f"Unexpected error: {e}")


@with_app_context
def update_l2vpn(filter_data, update_data):
    try:
        task_id = create_task(operation_type='update', task_type='l2vpn',
                              data={'filter_data': filter_data, 'update_data': update_data})
        l2vpn_id = filter_data['id']
        l2vpn = L2VPN.query.filter_by(id=l2vpn_id).first()
        l2vpn.task_id = task_id
        db.session.commit()
        if not l2vpn:
            print(f"L2VPN with ID {l2vpn_id} not found")
            return

        trunk1_circuit_id = update_data.get('trunk1_circuit_id')
        trunk2_circuit_id = update_data.get('trunk2_circuit_id')
        metadata_only = update_data.get('metadata', False)

        if metadata_only:
            if update_l2vpn_metadata(l2vpn, update_data):
                db.session.commit()
                task = Task.query.filter_by(id=task_id).first()
                task.status = 1
                print(f"Updated L2VPN metadata: {l2vpn.circuit_id}")
            else:
                print(f"Rollback executed: {l2vpn.circuit_id}")
                db.session.rollback()
        else:
            if trunk1_circuit_id and trunk2_circuit_id:
                print("Cannot update both trunks. Only one trunk at the time.")
                return
            elif trunk1_circuit_id:
                task = Task.query.filter_by(id=task_id).first()
                if update_l2vpn_trunk(l2vpn, trunk1_circuit_id, update_data, trunk_index=1):
                    task.status = 1
                    db.session.commit()
                    print(f"Updated L2VPN trunk1: {l2vpn.circuit_id}")
                else:
                    print(f"Operation on L2VPN rolled back: {l2vpn.circuit_id}")
                    db.session.rollback()
                    task.status = 2
                    db.session.commit()
            elif trunk2_circuit_id:
                task = Task.query.filter_by(id=task_id).first()
                if update_l2vpn_trunk(l2vpn, trunk2_circuit_id, update_data, trunk_index=2):
                    task.status = 1
                    db.session.commit()
                    print(f"Updated L2VPN trunk2: {l2vpn.circuit_id}")
                else:
                    print(f"Operation on L2VPN rolled back: {l2vpn.circuit_id}")
                    db.session.rollback()
                    task.status = 2
                    db.session.commit()
            else:
                print("No trunks specified, updating provided metadata on both routers")

    except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
        db.session.rollback()
        print(f"Error updating L2VPN: {e}")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error updating L2VPN: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()


def update_l2vpn_metadata(l2vpn, update_data):
    device1 = connect_and_lock(l2vpn.ac1.trunk.node.ipaddr, l2vpn.ac1.trunk.node.hwtypes.vendor,
                               l2vpn.ac1.trunk.node.hwtypes.model)
    device2 = connect_and_lock(l2vpn.ac2.trunk.node.ipaddr, l2vpn.ac2.trunk.node.hwtypes.vendor,
                               l2vpn.ac2.trunk.node.hwtypes.model)
    if 'cust_id' in update_data:
        l2vpn.cust_id = update_data['cust_id']
    if 'circuit_id' in update_data:
        l2vpn.circuit_id = update_data['circuit_id']
    if 'bw_bits' in update_data:
        l2vpn.bw_bits = update_data['bw_bits']
    if 'protected' in update_data:
        l2vpn.protected = update_data['protected']
        device1.create_l2vpn(l2vpn_id=l2vpn.id, iface=l2vpn.ac1.trunk.iface, unit=l2vpn.ac1.unit,
                             extra_community_name="cm-l2vpn-prot" if l2vpn.protected else "cm-l2vpn-unprot",
                             site_id=1)
        device2.create_l2vpn(l2vpn_id=l2vpn.id, iface=l2vpn.ac2.trunk.iface, unit=l2vpn.ac2.unit,
                             extra_community_name="cm-l2vpn-prot" if l2vpn.protected else "cm-l2vpn-unprot",
                             site_id=2)

    device1.create_ac(iface=l2vpn.ac1.trunk.iface, unit=l2vpn.ac1.unit, vlan_id=l2vpn.ac1.vlan_id,
                      cust_id=l2vpn.cust_id, circuit_id=l2vpn.circuit_id, bw_bits=l2vpn.bw_bits)
    device2.create_ac(iface=l2vpn.ac1.trunk.iface, unit=l2vpn.ac1.unit, vlan_id=l2vpn.ac1.vlan_id,
                      cust_id=l2vpn.cust_id, circuit_id=l2vpn.circuit_id, bw_bits=l2vpn.bw_bits)
    device1.diff()
    device2.diff()
    device1.commit_check()
    device2.commit_check()
    if input("Type YES to confirm: ") == "YES":
        commit_and_disconnect(device=device1, rollback=False)
        commit_and_disconnect(device=device2, rollback=False)
        return True
    else:
        commit_and_disconnect(device=device1, rollback=True)
        commit_and_disconnect(device=device2, rollback=True)
        return False


def update_l2vpn_trunk(l2vpn, trunk_circuit_id, update_data, trunk_index):
    trunk = Trunk.query.filter_by(circuit_id=trunk_circuit_id).first()
    if not trunk:
        print(f"Trunk not found: circuit_id={trunk_circuit_id}")
        return

    if trunk_index == 1:
        ac = l2vpn.ac1
        site_id = 1
        if l2vpn.ac2.trunk.node.id == trunk.node.id:
            print(f"Both sides are on the same Node, operation cancelled. ", end="")
            return False
    else:
        ac = l2vpn.ac2
        site_id = 2
        if l2vpn.ac1.trunk.node.id == trunk.node.id:
            print(f"Both sides are on the same Node, operation cancelled. ", end="")
            return False

    old_device = None
    device = connect_and_lock(trunk.node.ipaddr, trunk.node.hwtypes.vendor, trunk.node.hwtypes.model)
    # If Node is different, we need to delete the configuration from the old Node
    if trunk.node.id != ac.trunk.node.id:
        old_device = connect_and_lock(ac.trunk.node.ipaddr, ac.trunk.node.hwtypes.vendor, ac.trunk.node.hwtypes.model)
        old_device.delete_ac(ac.trunk.iface, ac.unit)
        old_device.delete_l2vpn(l2vpn_id=l2vpn.id, iface=ac.trunk.iface, unit=ac.unit)
        old_device.diff()
        ac.trunk_id = trunk.id
        ac.unit = device.get_free_unit(trunk.iface)
        if 'vlan_id' in update_data:
            ac.vlan_id = update_data['vlan_id']
    # If is the same Node and same trunk, delete the AC without changing the unit
    elif trunk.node.id == ac.trunk.node.id and trunk.id == ac.trunk.id:
        device.delete_ac(ac.trunk.iface, ac.unit)
        if 'vlan_id' in update_data:
            ac.vlan_id = update_data['vlan_id']
    # Else, move from one trunk to another on the same Node
    else:
        device.delete_ac(ac.trunk.iface, ac.unit)
        device.delete_l2vpn(l2vpn_id=l2vpn.id, iface=ac.trunk.iface, unit=ac.unit)
        ac.trunk_id = trunk.id
        ac.unit = device.get_free_unit(trunk.iface)
        if 'vlan_id' in update_data:
            ac.vlan_id = update_data['vlan_id']

    db.session.flush()

    device.create_ac(iface=ac.trunk.iface, unit=ac.unit, vlan_id=ac.vlan_id,
                     cust_id=l2vpn.cust_id, circuit_id=l2vpn.circuit_id, bw_bits=l2vpn.bw_bits)
    device.create_l2vpn(l2vpn_id=l2vpn.id, iface=ac.trunk.iface, unit=ac.unit,
                        extra_community_name="cm-l2vpn-prot" if l2vpn.protected else "cm-l2vpn-unprot",
                        site_id=site_id)
    if input("Type YES to confirm: ") == "YES":
        if old_device:
            commit_and_disconnect(device=old_device, rollback=False)
        commit_and_disconnect(device=device, rollback=False)
        return True
    else:
        if old_device:
            commit_and_disconnect(device=old_device, rollback=False)
        commit_and_disconnect(device=device, rollback=False)
        return False

@with_app_context
def delete_l2vpn(filter_data):
    if 'id' in filter_data:
        try:
            task_id = create_task(operation_type='delete', task_type='l2vpn', data=filter_data)
            l2vpn_id = filter_data['id']
            l2vpn = L2VPN.query.filter_by(id=l2vpn_id).first()
            if l2vpn:
                device1 = DummyDevice(host=l2vpn.ac1.trunk.node.ipaddr, user=router_user, passwd=router_password,
                                      hwmodel=l2vpn.ac1.trunk.node.hwtypes.model)
                device2 = DummyDevice(host=l2vpn.ac2.trunk.node.ipaddr, user=router_user, passwd=router_password,
                                      hwmodel=l2vpn.ac2.trunk.node.hwtypes.model)
                # Router related test code
                device1.connect()
                device2.connect()
                device1.lock_config()
                device2.lock_config()
                device1.delete_ac(l2vpn.ac1.trunk.iface, l2vpn.ac1.unit)
                device2.delete_ac(l2vpn.ac2.trunk.iface, l2vpn.ac2.unit)
                device1.delete_l2vpn(l2vpn_id, l2vpn.ac1.trunk.iface, l2vpn.ac1.unit)
                device2.delete_l2vpn(l2vpn_id, l2vpn.ac2.trunk.iface, l2vpn.ac2.unit)
                device1.diff()
                device2.diff()
                task = Task.query.filter_by(id=task_id).first()
                # End of router related test code
                if input("Type YES to confirm: ") == "YES":
                    commit_and_disconnect(device=device1, rollback=False)
                    commit_and_disconnect(device=device2, rollback=False)
                    db.session.delete(l2vpn)
                    db.session.delete(l2vpn.ac1)
                    db.session.delete(l2vpn.ac2)
                    task.status = 1
                    db.session.commit()
                else:
                    print("Executing a rollback")
                    commit_and_disconnect(device=device1, rollback=True)
                    commit_and_disconnect(device=device2, rollback=True)
                    db.session.rollback()
                    task.status = 1
                    db.session.commit()
                    return
                print(f"Deleted L2VPN with filter: {filter_data}")
            else:
                print("L2VPN not found.")
        except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
            db.session.rollback()
            commit_and_disconnect(device=device2, rollback=True)
            print(f"Error deleting L2VPN: {e}")
        except Exception as e:
            commit_and_disconnect(device=device2, rollback=True)
            print(f"Unexpected error: {e}")
    else:
        print("L2VPN id not specified.")

@with_app_context
def create_l3vpn(data):
    try:
        new_l3vpn = L3VPN(
            max_prefixes=data['max_prefixes'],
            circuit_id=data['circuit_id'],
            cust_id=data['cust_id']
        )
        db.session.add(new_l3vpn)
        db.session.commit()
        print("L3VPN created successfully!")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error creating Node: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def read_l3vpn(filter_data=None, tree_view=False):
    try:
        if 'id' in filter_data:
            print(f"Filter data provided: {filter_data}")
            l3vpns = L3VPN.query.filter_by(**filter_data).all()
        else:
            l3vpns = L3VPN.query.all()
        if l3vpns:
            for l3vpn in l3vpns:
                print(l3vpn.to_yaml(tree_view=tree_view))
        else:
            print("Message: No L3VPN found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

@with_app_context
def update_l3vpn(filter_data, update_data):
    print(f"Updating L3VPN with filter: {filter_data}, data: {update_data}")
    try:
        l3vpn_id = filter_data['id']
        l3vpn = L3VPN.query.filter_by(id=l3vpn_id).first()
        task_id = create_task(operation_type='update', task_type='l3vpn', data={'filter_data': filter_data, 'updata_data': update_data})
        if l3vpn:
            for key, value in update_data.items():
                setattr(l3vpn, key, value)
            devices = []
            devices_count = 0
            db.session.flush()
            hubs = L3VPNHub.query.filter_by(l3vpn_id=l3vpn.id)

            if 'recursive' in update_data:
                print("Updating all hubs...")
                for hub in hubs:
                    devices.append(connect_and_lock(ipaddr=hub.node.ipaddr, vendor=hub.node.hwtypes.vendor,
                                                    model=hub.node.hwtypes.model))
                    devices[devices_count].create_l3vpnhub(l3vpn_id=l3vpn.id, max_prefixes=l3vpn.max_prefixes)
                    devices[devices_count].commit_check()
                    devices[devices_count].diff()
                    devices_count = devices_count + 1
                task = Task.query.filter_by(id=task_id).first()
                if input("Type YES to confirm: ") == "YES":
                    for device in devices:
                        commit_and_disconnect(device=device, rollback=False)
                    task.status = 1
                    db.session.commit()
                    print(f"L3VPN updated with data: {update_data} on all Hubs")
                else:
                    for device in devices:
                        commit_and_disconnect(device=device, rollback=True)
                    db.session.rollback()
                    task.status = 2
                    db.session.commit()
            else:
                db.session.commit()
                print(f"L3VPN updated with data: {update_data}")
        else:
            print("L3VPN not found.")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error updating L3VPN: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def delete_l3vpn(filter_data):
    try:
        l3vpn_id = filter_data['id']
        l3vpn = L3VPN.query.filter_by(id=l3vpn_id).first()
        if l3vpn:
            db.session.delete(l3vpn)
            db.session.commit()
            print(f"Deleting L3VPN with filter: {filter_data}")
        else:
            print("L3VPN not found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

@with_app_context
def create_l3vpnhub(data):
    try:
        task_id = create_task(operation_type='create', task_type='l3vpnhub', data=data)
        node_name = data['node_name']
        site_tag = data['site_tag']
        node = Node.query.join(Site).filter(Node.name == node_name, Site.tag == site_tag).first()
        if not node:
            print("Node not found.")
            return

        l3vpn = L3VPN.query.filter_by(id=data['l3vpn_id']).first()
        if not l3vpn:
            print("L3VPN not found.")
            return

        device = connect_and_lock(node.ipaddr, node.hwtypes.vendor, node.hwtypes.model)
        new_l3vpnhub = L3VPNHub(
            l3vpn_id=data['l3vpn_id'],
            node_id=node.id
        )

        db.session.add(new_l3vpnhub)
        db.session.flush()  # Flush to send changes to the database

        # Access related L3VPN object
        l3vpn_max_prefixes = new_l3vpnhub.l3vpn.max_prefixes
        print(f"Max prefixes for the associated L3VPN: {l3vpn_max_prefixes}")

        device.create_l3vpnhub(l3vpn_id=new_l3vpnhub.l3vpn_id, max_prefixes=l3vpn_max_prefixes)
        device.diff()
        device.commit_check()

        if input("Type YES to confirm: ") == "YES":
            task = Task.query.filter_by(id=task_id)
            task.status = 1
            db.session.commit()
            commit_and_disconnect(device=device, rollback=False)
            print("L3VPNHub created successfully!")
        else:
            db.session.rollback()
            commit_and_disconnect(device=device, rollback=True)
    except SQLAlchemyError as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Error creating L3VPNHub: {e}")
    except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Error creating L3VPNHub router config: {e}")
    except Exception as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def read_l3vpnhub(filter_data=None, tree_view=False):
    try:
        if filter_data:
            print(f"Filter data provided: {filter_data}")
            l3vpnhubs = L3VPNHub.query.filter_by(**filter_data).all()
        else:
            l3vpnhubs = L3VPNHub.query.all()
        if l3vpnhubs:
            for l3vpnhub in l3vpnhubs:
                print(l3vpnhub.to_yaml(tree_view=tree_view))
        else:
            print("Message: No L3VPNHub found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

@with_app_context
def update_l3vpnhub(filter_data, update_data):
    print(f"Updating L3VPNHub with filter: {filter_data}, data: {update_data}")
    try:
        task_id = create_task(operation_type='update', task_type='l3vpnhub', data={'filter_data': filter_data,
                                                                                   'update_data': update_data})
        l3vpnhub_id = filter_data['id']
        l3vpnhub = L3VPNHub.query.filter_by(id=l3vpnhub_id).first()
        device = None
        if l3vpnhub:
            device = connect_and_lock(ipaddr=l3vpnhub.node.ipaddr, vendor=l3vpnhub.node.hwtypes.vendor,
                                      model=l3vpnhub.node.hwtypes.model)
            device.create_l3vpnhub(l3vpn_id=l3vpnhub.l3vpn_id, max_prefixes=l3vpnhub.l3vpn.max_prefixes)
            device.diff()
            device.commit_check()
            if input("Type YES to confirm: ") == "YES":
                task = Task.query.filter_by(id=task_id).first()
                task.status = 1
                db.session.commit()
                commit_and_disconnect(device=device, rollback=False)
            else:
                db.session.rollback()
                commit_and_disconnect(device=device, rollback=True)
        else:
            print("L3VPNHub not found.")
    except SQLAlchemyError as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Error updating L3VPNHub: {e}")
    except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Error updating L3VPNHub router config: {e}")
    except Exception as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def delete_l3vpnhub(filter_data):
    try:
        print("asd")
        l3vpnhub_id = filter_data['id']
        l3vpnhub = L3VPNHub.query.filter_by(id=l3vpnhub_id).first()
        task_id = create_task(operation_type='delete', task_type='l3vpnhub', data=filter_data)
        device = None
        if l3vpnhub:
            device = connect_and_lock(ipaddr=l3vpnhub.node.ipaddr, vendor=l3vpnhub.node.hwtypes.vendor, model=l3vpnhub.node.hwtypes.model)
            device.delete_l3vpnhub(l3vpn_id=l3vpnhub.l3vpn_id)
            print(f"Deleting L3VPNHub with filter: {filter_data}")
            if input("Type YES to confirm: ") == "YES":
                db.session.delete(l3vpnhub)
                db.session.commit()
                commit_and_disconnect(device=device, rollback=False)
            else:
                print("Executing a rollback")
                db.session.rollback()
                commit_and_disconnect(device=device, rollback=True)

        else:
            print("L3VPNHub not found.")
    except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=False)
        print(f"Error deleting L3VPNHub router config: {e}")
    except Exception as e:
        commit_and_disconnect(device=device, rollback=True)
        print(f"Unexpected error: {e}")

@with_app_context
def create_l3vpnce(data):
    try:
        task_id = create_task(operation_type='create', task_type='l3vpnce', data=data)
        trunk_circuit_id = data['trunk_circuit_id']
        trunk = Trunk.query.filter_by(circuit_id=trunk_circuit_id).first()
        hub_id = data['hub_id']
        hub = L3VPNHub.query.filter_by(id=hub_id).first()
        inet_prefix = data['inet_prefix']
        inet6_prefix = data['inet_prefix']
        if trunk.node.id != hub.node.id:
            print(f"Trunk {trunk_circuit_id} not found in hub {hub.id}. Operation cancelled")
            return
        device = connect_and_lock(trunk.node.ipaddr, trunk.node.hwtypes.vendor, trunk.node.hwtypes.model)
        bw_bits = data['bw_bits']
        new_ac = AC(
            trunk_id=trunk.id,
            vlan_id=data.get('vlan_id'),
            unit=device.get_free_unit(trunk.iface)
        )
        db.session.add(new_ac)
        db.session.flush()
        new_l3vpnce = L3VPNCE(
            hub_id=hub.id,
            trunk_id=trunk.id,
            ac_id=new_ac.id,
            circuit_id=data['circuit_id'],
            inet_prefix=data['inet_prefix'],
            inet6_prefix=data['inet6_prefix'],
            bw_bits=bw_bits,
            peer_as=data['peer_as']
        )
        db.session.add(new_l3vpnce)
        db.session.flush()  # Flush to send changes to the database
        l3vpn = L3VPN.query.filter_by(id=hub.l3vpn_id).first()
        device.create_ac(iface=new_ac.trunk.iface, unit=new_ac.unit, vlan_id=new_ac.vlan_id, bw_bits=new_l3vpnce.bw_bits,
                         circuit_id=new_l3vpnce.circuit_id, cust_id=l3vpn.cust_id)
        device.create_l3vpnce(l3vpn_id=l3vpn.id, inet_prefix=inet_prefix, inet6_prefix=inet6_prefix,
                              peer_as=new_l3vpnce.peer_as, iface_unit=f"{new_ac.trunk.iface}.{new_ac.unit}")
        device.commit_check()
        device.diff()
        if input("Type YES to confirm: ") == "YES":
            task = Task.query.filter_by(id=task_id).first()
            task.status = 1
            print(f"L3VPNCE created for hub: {hub.id}, trunk_circuit_id: {trunk_circuit_id}, ac: {new_ac.id}")
            db.session.commit()
            commit_and_disconnect(device=device, rollback=False)
            print("L3VPNCE created successfully!")
        else:
            print("Operation cancelled. Rolling back config and database.")
            commit_and_disconnect(device=device, rollback=True)
            db.session.rollback()
    except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Error creating L3VPNCE on hub: {e}")
    except SQLAlchemyError as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Error creating L3VPNCE: {e}")
    except Exception as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()


@with_app_context
def read_l3vpnce(filter_data=None, tree_view=False):
    try:
        if filter_data:
            print(f"Filter data provided: {filter_data}")
            l3vpnces = L3VPNCE.query.filter_by(**filter_data).all()
        else:
            l3vpnces = L3VPNCE.query.all()
        if l3vpnces:
            for l3vpnce in l3vpnces:
                print(l3vpnce.to_yaml(tree_view=tree_view))
        else:
            print("Message: No L3VPNCE found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

def update_l3vpnce(filter_data, update_data):
    delete_l3vpnce(filter_data)
    create_l3vpnce(update_data)

@with_app_context
def delete_l3vpnce(filter_data, from_update=False):
    try:
        task_id = create_task(operation_type='delete', task_type='l3vpnce', data=filter_data)
        l3vpnce_circuit_id = filter_data['circuit_id']
        l3vpnce = L3VPNCE.query.filter_by(circuit_id=l3vpnce_circuit_id).first()
        hub = l3vpnce.hub
        ac = l3vpnce.ac
        if l3vpnce:
            device = connect_and_lock(ipaddr=hub.node.ipaddr, vendor=hub.node.hwtypes.vendor, model=hub.node.hwtypes.model)
            device.delete_ac(iface=ac.trunk.iface, unit=ac.unit)
            device.delete_l3vpnce(l3vpn_id=hub.l3vpn_id, inet_prefix=l3vpnce.inet_prefix, inet6_prefix=l3vpnce.inet6_prefix)
            device.commit_check()
            device.diff()
            if input("Type YES to confirm: ") == "YES":
                task = Task.query.filter_by(id=task_id).first()
                task.status = 1
                db.session.delete(l3vpnce)
                db.session.delete(ac)
                db.session.commit()
                commit_and_disconnect(device=device, rollback=False)
                return True
            else:
                db.session.rollback()
                commit_and_disconnect(device=device, rollback=True)
            print(f"Deleting L3VPNCE with filter: {filter_data}")
        else:
            print("L3VPNCE not found.")
    except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
        db.session.rollback()
    except SQLAlchemyError as e:
        commit_and_disconnect(device=device, rollback=True)
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def create_evpn(data):
    try:
        new_evpn = EVPN(
            mac_address_table_limit=data['mac_address_table_limit'],
            circuit_id=data['circuit_id'],
            cust_id=data['cust_id']
        )
        db.session.add(new_evpn)
        db.session.commit()
        print("EVPN created successfully!")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error creating EVPN: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()


@with_app_context
def read_evpn(filter_data=None, tree_view=False):
    try:
        if filter_data:
            print(f"Filter data provided: {filter_data}")
            evpns = EVPN.query.filter_by(**filter_data).all()
        else:
            evpns = EVPN.query.all()
        if evpns:
            for evpn in evpns:
                print(evpn.to_yaml(tree_view=tree_view))
        else:
            print("Message: No EVPN found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

@with_app_context
def update_evpn(filter_data, update_data):
    print(f"Updating EVPN with filter: {filter_data}, data: {update_data}")
    try:
        evpn_id = filter_data['id']
        evpn = EVPN.query.filter_by(id=evpn_id).first()
        task_id = create_task(operation_type='update', task_type='evpn', data={'filter_data': filter_data, 'updata_data': update_data})
        if evpn:
            for key, value in update_data.items():
                setattr(evpn, key, value)
            devices = []
            devices_count = 0
            db.session.flush()
            hubs = EVPNHub.query.filter_by(evpn_id=evpn.id).all()

            if 'recursive' in update_data:
                print("Updating all hubs...")
                for hub in hubs:
                    devices.append(connect_and_lock(ipaddr=hub.node.ipaddr, vendor=hub.node.hwtypes.vendor,
                                                    model=hub.node.hwtypes.model))
                    devices[devices_count].create_evpnhub(evpn_id=evpn.id, mac_address_table_limit=evpn.mac_address_table_limit,
                                                          split_horizon=hub.split_horizon, designated_forwarder=hub.designated_forwarder,
                                                          route_targets=hub.route_targets, extended_communities=hub.extended_communities)
                    devices[devices_count].commit_check()
                    devices[devices_count].diff()
                    devices_count = devices_count + 1
                task = Task.query.filter_by(id=task_id).first()
                if input("Type YES to confirm: ") == "YES":
                    for device in devices:
                        commit_and_disconnect(device=device, rollback=False)
                    task.status = 1
                    db.session.commit()
                    print(f"EVPN updated with data: {update_data} on all Hubs")
                else:
                    for device in devices:
                        commit_and_disconnect(device=device, rollback=True)
                    db.session.rollback()
                    task.status = 2
                    db.session.commit()
            else:
                db.session.commit()
                print(f"EVPN updated with data: {update_data}")
        else:
            print("EVPN not found.")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error updating EVPN: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def delete_evpn(filter_data):
    try:
        evpn_id = filter_data['id']
        evpn = EVPN.query.filter_by(id=evpn_id).first()
        if evpn:
            db.session.delete(evpn)
            db.session.commit()
            print(f"Deleting EVPN with filter: {filter_data}")
        else:
            print("EVPN not found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

@with_app_context
def create_evpnhub(data):
    try:
        task_id = create_task(operation_type='create', task_type='evpnhub', data=data)
        node_name = data['node_name']
        site_tag = data['site_tag']
        node = Node.query.join(Site).filter(Node.name == node_name, Site.tag == site_tag).first()
        if not node:
            print("Node not found.")
            return

        evpn = EVPN.query.filter_by(id=data['evpn_id']).first()
        if not evpn:
            print("EVPN not found.")
            return

        device = connect_and_lock(node.ipaddr, node.hwtypes.vendor, node.hwtypes.model)
        new_evpnhub = EVPNHub(
            evpn_id=data['evpn_id'],
            node_id=node.id,
            split_horizon=data['split_horizon'],
            designated_forwarder=data['designated_forwarder'],
            route_targets=data['route_targets'] if 'route_targets' in data else None,
            extended_communities=data['extended_communities'] if 'extended_communities' in data else None
        )

        db.session.add(new_evpnhub)
        db.session.flush()

        device.create_evpnhub(evpn_id=new_evpnhub.evpn_id, extended_communities=new_evpnhub.extended_communities,
                              split_horizon=new_evpnhub.split_horizon, designated_forwarder=new_evpnhub.designated_forwarder,
                              route_targets=new_evpnhub.route_targets)
        device.diff()
        device.commit_check()

        if input("Type YES to confirm: ") == "YES":
            task = Task.query.filter_by(id=task_id)
            task.status = 1
            db.session.commit()
            commit_and_disconnect(device=device, rollback=False)
            print("EVPNHub created successfully!")
        else:
            db.session.rollback()
            commit_and_disconnect(device=device, rollback=True)
    except SQLAlchemyError as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Error creating EVPNHub: {e}")
    except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Error creating EVPNHub router config: {e}")
    except Exception as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def read_evpnhub(filter_data=None, tree_view=False):
    try:
        if filter_data:
            print(f"Filter data provided: {filter_data}")
            evpnhubs = EVPNHub.query.filter_by(**filter_data).all()
        else:
            evpnhubs = EVPNHub.query.all()
        if evpnhubs:
            for evpnhub in evpnhubs:
                print(evpnhub.to_yaml(tree_view=tree_view))
        else:
            print("Message: No EVPNHub found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

@with_app_context
def update_evpnhub(filter_data, update_data):
    print(f"Updating EVPNHub with filter: {filter_data}, data: {update_data}")
    try:
        task_id = create_task(operation_type='update', task_type='evpnhub', data={'filter_data': filter_data, 'update_data': update_data})
        evpnhub_id = filter_data['id']
        evpnhub = EVPNHub.query.filter_by(id=evpnhub_id).first()
        device = None
        if evpnhub:
            device = connect_and_lock(ipaddr=evpnhub.node.ipaddr, vendor=evpnhub.node.hwtypes.vendor, model=evpnhub.node.hwtypes.model)
            device.create_evpnhub(evpn_id=evpnhub.evpn_id)
            device.diff()
            device.commit_check()
            if input("Type YES to confirm: ") == "YES":
                task = Task.query.filter_by(id=task_id).first()
                task.status = 1
                db.session.commit()
                commit_and_disconnect(device=device, rollback=False)
            else:
                db.session.rollback()
                commit_and_disconnect(device=device, rollback=True)
        else:
            print("EVPNHub not found.")
    except SQLAlchemyError as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Error updating EVPNHub: {e}")
    except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Error updating EVPNHub router config: {e}")
    except Exception as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def delete_evpnhub(filter_data):
    try:
        evpnhub_id = filter_data['id']
        evpnhub = EVPNHub.query.filter_by(id=evpnhub_id).first()
        task_id = create_task(operation_type='delete', task_type='evpnhub', data=filter_data)
        device = None
        if evpnhub:
            device = connect_and_lock(ipaddr=evpnhub.node.ipaddr, vendor=evpnhub.node.hwtypes.vendor, model=evpnhub.node.hwtypes.model)
            device.delete_evpnhub(evpn_id=evpnhub.evpn_id)
            print(f"Deleting EVPNHub with filter: {filter_data}")
            if input("Type YES to confirm: ") == "YES":
                db.session.delete(evpnhub)
                db.session.commit()
                commit_and_disconnect(device=device, rollback=False)
            else:
                db.session.rollback()
                commit_and_disconnect(device=device, rollback=True)
        else:
            print("EVPNHub not found.")
    except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=False)
        print(f"Error deleting EVPNHub router config: {e}")
    except Exception as e:
        commit_and_disconnect(device=device, rollback=True)
        print(f"Unexpected error: {e}")

@with_app_context
def create_evpnce(data):
    try:
        task_id = create_task(operation_type='create', task_type='evpnce', data=data)
        trunk_circuit_id = data['trunk_circuit_id']
        trunk = Trunk.query.filter_by(circuit_id=trunk_circuit_id).first()
        hub_id = data['hub_id']
        hub = EVPNHub.query.filter_by(id=hub_id).first()
        if trunk.node.id != hub.node.id:
            print(f"Trunk {trunk_circuit_id} not found in hub {hub.id}. Operation cancelled")
            return
        device = connect_and_lock(trunk.node.ipaddr, trunk.node.hwtypes.vendor, trunk.node.hwtypes.model)
        new_ac = AC(
            trunk_id=trunk.id,
            vlan_id=data.get('vlan_id'),
            unit=device.get_free_unit(trunk.iface)
        )
        db.session.add(new_ac)
        db.session.flush()
        new_evpnce = EVPNCE(
            hub_id=hub.id,
            ac_id=new_ac.id,
            circuit_id=data['circuit_id']
        )
        db.session.add(new_evpnce)
        db.session.flush()
        evpn = EVPN.query.filter_by(id=hub.evpn_id).first()
        device.create_ac(iface=new_ac.trunk.iface, unit=new_ac.unit, vlan_id=new_ac.vlan_id, circuit_id=new_evpnce.circuit_id, cust_id=evpn.cust_id)
        device.create_evpnce(evpn_id=evpn.id, iface_unit=f"{new_ac.trunk.iface}.{new_ac.unit}")
        device.commit_check()
        device.diff()
        if input("Type YES to confirm: ") == "YES":
            task = Task.query.filter_by(id=task_id).first()
            task.status = 1
            db.session.commit()
            commit_and_disconnect(device=device, rollback=False)
            print("EVPNCE created successfully!")
        else:
            commit_and_disconnect(device=device, rollback=True)
            db.session.rollback()
    except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Error creating EVPNCE on hub: {e}")
    except SQLAlchemyError as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Error creating EVPNCE: {e}")
    except Exception as e:
        db.session.rollback()
        commit_and_disconnect(device=device, rollback=True)
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def read_evpnce(filter_data=None, tree_view=False):
    try:
        if filter_data:
            print(f"Filter data provided: {filter_data}")
            evpnces = EVPNCE.query.filter_by(**filter_data).all()
        else:
            evpnces = EVPNCE.query.all()
        if evpnces:
            for evpnce in evpnces:
                print(evpnce.to_yaml(tree_view=tree_view))
        else:
            print("Message: No EVPNCE found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

def update_evpnce(filter_data, update_data):
    delete_evpnce(filter_data)
    create_evpnce(update_data)

@with_app_context
def delete_evpnce(filter_data):
    try:
        task_id = create_task(operation_type='delete', task_type='evpnce', data=filter_data)
        evpnce_circuit_id = filter_data['circuit_id']
        evpnce = EVPNCE.query.filter_by(circuit_id=evpnce_circuit_id).first()
        hub = evpnce.hub
        ac = evpnce.ac
        if evpnce:
            device = connect_and_lock(ipaddr=hub.node.ipaddr, vendor=hub.node.hwtypes.vendor, model=hub.node.hwtypes.model)
            device.delete_ac(iface=ac.trunk.iface, unit=ac.unit)
            device.delete_evpnce(evpn_id=hub.evpn_id)
            device.commit_check()
            device.diff()
            if input("Type YES to confirm: ") == "YES":
                task = Task.query.filter_by(id=task_id).first()
                task.status = 1
                db.session.delete(evpnce)
                db.session.delete(ac)
                db.session.commit()
                commit_and_disconnect(device=device, rollback=False)
                return True
            else:
                db.session.rollback()
                commit_and_disconnect(device=device, rollback=True)
            print(f"Deleting EVPNCE with filter: {filter_data}")
        else:
            print("EVPNCE not found.")
    except (RouterLockError, RouterConfigError, RouterConnectionError, RouterAuthError) as e:
        db.session.rollback()
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def create_rt(data):
    try:
        new_rt = RT(
            description=data['description'],
            target=data['target']
        )
        db.session.add(new_rt)
        db.session.commit()
        print(f"Created RT: {new_rt.target}")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error creating RT on database. Error: {e}")
    finally:
        db.session.close()

@with_app_context
def read_rt(filter_data=None, tree_view=False):
    try:
        if 'id' in filter_data:
            rt_id = filter_data['id']
            rt = RT.query.filter_by(id=rt_id).first()
            if rt:
                print(rt.to_yaml())
            else:
                print("RT not found.")
        else:
            rts = RT.query.all()
            if rts:
                for rt in rts:
                    print(rt.to_yaml())
            else:
                print("No RTs found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

@with_app_context
def update_rt(filter_data, update_data):
    try:
        rt_id = filter_data['id']
        rt = RT.query.filter_by(id=rt_id).first()
        if rt:
            for key, value in update_data.items():
                setattr(rt, key, value)
            db.session.commit()
            print("RT updated successfully.")
            print(rt.to_yaml())
        else:
            print("RT not found")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error updating RT: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def delete_rt(filter_data):
    try:
        rt_id = filter_data['id']
        rt = RT.query.filter_by(id=rt_id).first()
        if rt:
            db.session.delete(rt)
            db.session.commit()
            print(f"Deleted RT with ID: {rt_id}")
        else:
            print("RT not found.")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def create_instance(data):
    try:
        node_name = data['pe_name']
        site_tag = data['site_tag']
        rt_description = data['rt_description']
        node = Node.query.join(Site).filter(Node.name == node_name, Site.tag == site_tag).first()
        rt = RT.query.filter_by(description=rt_description).first()
        print(rt.id)
        if not node:
            print(f"Node not found with name: {node_name} and site tag: {site_tag}")
            return
        if not rt:
            print(f"RT not found with description: {rt_description}")
            return
        new_instance = Instance(
            name=data['name'],
            node_id=node.id,
            type=data['type'],
            rt_id=rt.id
        )

        db.session.add(new_instance)
        db.session.commit()

        print(f"Created Instance: {new_instance.name}")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error creating Instance on database. Error: {e}")
    finally:
        db.session.close()

@with_app_context
def read_instance(filter_data=None, tree_view=False):
    try:
        if 'name' in filter_data:
            name = filter_data['name']
            instance = Instance.query.filter_by(name=name).first()
            if instance:
                print(instance.to_yaml(tree_view))
            else:
                print("Instance not found.")
        else:
            instances = Instance.query.all()
            if instances:
                for instance in instances:
                    print(instance.to_yaml(tree_view))
            else:
                print("No Instances found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

@with_app_context
def update_instance(filter_data, update_data):
    try:
        name = filter_data['name']
        instance = Instance.query.filter_by(name=name).first()
        if instance:
            # Creating task
            task_id = create_task(operation_type='update', task_type='instance',
                                  data={'filter': filter_data, 'update_data': update_data})

            for key, value in update_data.items():
                setattr(instance, key, value)

            db.session.commit()

            task = Task.query.filter_by(id=task_id).first()
            task.status = 1
            db.session.commit()

            print("Instance updated successfully.")
            print(instance.to_yaml())
        else:
            print("Instance not found")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error updating Instance: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def delete_instance(filter_data):
    try:
        name = filter_data['name']
        instance = Instance.query.filter_by(name=name).first()
        if instance:
            # Creating task
            task_id = create_task(operation_type='delete', task_type='instance', data=filter_data)

            db.session.delete(instance)
            db.session.commit()

            task = Task.query.filter_by(id=task_id).first()
            task.status = 1
            db.session.commit()

            print(f"Deleted Instance with name: {name}")
        else:
            print("Instance not found.")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def create_bgpgroup(data):
    try:
        instance_name = data['instance_name']
        instance = Instance.query.filter_by(name=instance_name).first()
        if not instance:
            print(f"Instance not found with name: {instance_name}")
            return
        new_bgpgroup = BGPGroup(
            name=data['name'],
            peeras=data['peeras'] if 'peeras' in data else 0,
            instance_id=instance.id
        )
        db.session.add(new_bgpgroup)
        db.session.commit()
        print(f"Created BGPGroup: {new_bgpgroup.name}")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error creating BGPGroup on database. Error: {e}")
    finally:
        db.session.close()

@with_app_context
def read_bgpgroup(filter_data=None, tree_view=False):
    try:
        if 'name' in filter_data:
            bgpgroup_name = filter_data['name']
            bgpgroup = BGPGroup.query.filter_by(name=bgpgroup_name).first()
            if bgpgroup:
                print(bgpgroup.to_yaml())
            else:
                print(f"BGPGroup name {bgpgroup_name} not found.")
        else:
            bgpgroups = BGPGroup.query.all()
            if bgpgroups:
                for bgpgroup in bgpgroups:
                    print(bgpgroup.to_yaml())
            else:
                print("No BGPGroups found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

@with_app_context
def update_bgpgroup(filter_data, update_data):
    try:
        bgpgroup_id = filter_data['id']
        bgpgroup = BGPGroup.query.filter_by(id=bgpgroup_id).first()
        if bgpgroup:
            for key, value in update_data.items():
                setattr(bgpgroup, key, value)
            db.session.commit()
            print("BGPGroup updated successfully.")
            print(bgpgroup.to_yaml())
        else:
            print("BGPGroup not found")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error updating BGPGroup: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def delete_bgpgroup(filter_data):
    try:
        bgpgroup_id = filter_data['id']
        bgpgroup = BGPGroup.query.filter_by(id=bgpgroup_id).first()
        if bgpgroup:
            db.session.delete(bgpgroup)
            db.session.commit()
            print(f"Deleted BGPGroup with ID: {bgpgroup_id}")
        else:
            print("BGPGroup not found.")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def create_neighbor(data):
    try:
        new_neighbor = Neighbor(
            ipaddr=data['ipaddr'],
            description=data.get('description'),
            bgpgroup_id=data['bgpgroup_id'],
            peeras=data.get('peeras') if 'peeras' in data else 0,
            export_policy=data.get('export_policy') if 'export_policy' in data else 'none'
        )
        db.session.add(new_neighbor)
        db.session.commit()
        print(f"Created Neighbor: {new_neighbor.ipaddr}")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error creating Neighbor on database. Error: {e}")
    finally:
        db.session.close()

@with_app_context
def read_neighbor(filter_data=None, tree_view=False):
    try:
        if 'id' in filter_data:
            neighbor_id = filter_data['id']
            neighbor = Neighbor.query.filter_by(id=neighbor_id).first()
            if neighbor:
                print(neighbor.to_yaml())
            else:
                print("Neighbor not found.")
        elif 'ipaddr' in filter_data:
            ipaddr = filter_data['ipaddr']
            neighbors = Neighbor.query.filter_by(ipaddr=ipaddr).all()
            for neighbor in neighbors:
                print(neighbor.to_yaml())
        else:
            neighbors = Neighbor.query.all()
            if neighbors:
                for neighbor in neighbors:
                    print(neighbor.to_yaml())
            else:
                print("No Neighbors found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

@with_app_context
def update_neighbor(filter_data, update_data):
    try:
        neighbor_id = filter_data['id']
        neighbor = Neighbor.query.filter_by(id=neighbor_id).first()
        if neighbor:
            for key, value in update_data.items():
                setattr(neighbor, key, value)
            db.session.commit()
            print("Neighbor updated successfully.")
            print(neighbor.to_dict())
        else:
            print("Neighbor not found")
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error updating Neighbor: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()

@with_app_context
def delete_neighbor(filter_data):
    try:
        neighbor_id = filter_data['id']
        neighbor = Neighbor.query.filter_by(id=neighbor_id).first()
        if neighbor:
            db.session.delete(neighbor)
            db.session.commit()
            print(f"Deleted Neighbor with ID: {neighbor_id}")
        else:
            print("Neighbor not found.")
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error: {e}")
    finally:
        db.session.close()
