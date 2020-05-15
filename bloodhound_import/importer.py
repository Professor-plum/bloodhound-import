"""
    Bloodhound importer in python.
    Queries are borrowed from the BloodhoundAD project.
"""

import codecs
import json
import logging

from neo4j import GraphDatabase

ACETYPE_MAP = {
    "All": "AllExtendedRights",
    "User-Force-Change-Password": "ForceChangePassword",
    "Member": "AddMember",
    "AddMember": "AddMember",
    "AllowedToAct": "AddAllowedToAct",
}

RIGHTS_MAP = {
    "GenericAll": "GenericAll",
    "WriteDacl": "WriteDacl",
    "WriteOwner": "WriteOwner",
    "GenericWrite": "GenericWrite",
    "Owner": "Owns",
    "ReadLAPSPassword": "ReadLAPSPassword"
}

SYNC_COUNT = 100

def process_ace_list(tx, ace_list, objid, objtype):
    """Process the list of aces.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        ace_list {list} -- Aces to parse.
        objid {str} -- ID of the object: computername, groupname etc.
        objtype {str} -- Type of the object: Computer, User, Group etc.
    """
    count = 0
    baseAceQuery = "UNWIND {{props}} AS prop MERGE (a:{} {{objectid:prop.principal}}) MERGE (b:{} {{objectid: prop.obj}}) MERGE (a)-[r:{} {{isacl:true}}]->(b)"

    for entry in ace_list:
        principal = entry['PrincipalSID']
        principaltype = entry['PrincipalType']
        right = entry['RightName']
        acetype = entry['AceType']

        if objid == principal:
            continue

        rights = []
        if acetype in ACETYPE_MAP:
            rights.append(ACETYPE_MAP[acetype])
        elif right == "ExtendedRight":
            rights.append(acetype)

        if right in RIGHTS_MAP:
            rights.append(RIGHTS_MAP[right])

        for right in rights:
            query = baseAceQuery.format(principaltype.title(), objtype, right)
            tx.run(query, props={'principal': principal, 'obj': objid})
            count += 1
            if count % SYNC_COUNT == 0:
                tx.sync()


def add_constraints(tx):
    """Adds bloodhound contraints to neo4j

    Arguments:
        tx {neo4j.Session} -- Neo4j session.
    """

    tx.run("CREATE CONSTRAINT ON (c:Base) ASSERT c.objectid IS UNIQUE")
    #tx.run("CREATE INDEX name_index FOR (n:Base) ON (n.name)")
    #tx.run("CREATE CONSTRAINT ON (c:Computer) ASSERT c.objectid IS UNIQUE")
    #tx.run("CREATE CONSTRAINT ON (c:Group) ASSERT c.objectid IS UNIQUE")
    #tx.run("CREATE CONSTRAINT ON (c:Domain) ASSERT c.name IS UNIQUE")
    #tx.run("CREATE CONSTRAINT ON (c:OU) ASSERT c.guid IS UNIQUE")
    #tx.run("CREATE CONSTRAINT ON (c:GPO) ASSERT c.name IS UNIQUE")


def create_computer_query(tx, computer, query, value, rel):
    """Creates the queries for a computer.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        computer {dict} -- Single computer object.
        query {str} -- Query to use.
        value {[type]} -- Value to read from: LocalAdmins, DcomUsers or RemoteDesktopUsers
        rel {[type]} -- Value to set: AdminTo, ExecuteDCOM or CanRDP
    """
    count = 0
    for entry in computer.get(value, []) or []:
        aType = entry['MemberType']
        aName = entry['MemberId']
        statement = query.format(aType, rel)
        props = {'objectid': computer['ObjectIdentifier'], 'target': aName}
        tx.run(statement, props=props)
        count += 1
        if count % SYNC_COUNT == 0:
            tx.sync()


def parse_ou(tx, ou):
    """Parses a single ou.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        gpo {dict} -- Single gpo object.
    """
    guid = ou['ObjectIdentifier']
    properties = ou['Properties']
    property_query = "UNWIND {props} AS prop MERGE (n:OU {objectid:prop.guid}) SET n += prop.map"
    tx.run(property_query, props={'guid': guid, 'map': properties})
    count = 0
    if 'Links' in ou and ou['Links'] is not None:
        link_query = "UNWIND {props} as prop MERGE (n:OU {objectid:prop.guid}) MERGE (m:GPO {objectid:prop.gpo}) MERGE (m)-[r:GpLink {enforced:prop.enforced, isacl:false}]->(n)"
        for link in ou['Links']:
            enforced = link['IsEnforced']
            target = link['Guid']
            tx.run(link_query, props={'guid': guid, 'gpo': target, 'enforced': enforced})
            count += 1
            if count % SYNC_COUNT == 0:
                tx.sync()

    if 'ChildOus' in ou and ou['ChildOus'] is not None:
        childou_query = "UNWIND {props} AS prop MERGE (n:OU {objectid:prop.parent}) MERGE (m:OU {object-id:prop.child}) MERGE (n)-[r:Contains {isacl:false}]->(m)"
        for cou in ou['ChildOus']:
            tx.run(childou_query, props={'parent': guid, 'child': cou})
            count += 1
            if count % SYNC_COUNT == 0:
                tx.sync()

    if 'Computers' in ou and ou['Computers'] is not None:
        computer_query = "UNWIND {props} AS prop MERGE (n:OU {objectid:prop.ou}) MERGE (m:Computer {objectid:prop.comp}) MERGE (n)-[r:Contains {isacl:false}]->(m)"
        for computer in ou['Computers']:
            tx.run(computer_query, props={'ou': guid, 'comp': computer})
            count += 1
            if count % SYNC_COUNT == 0:
                tx.sync()

    if 'Users' in ou and ou['Users'] is not None:
        user_query = "UNWIND {props} AS prop MERGE (n:OU {objectid:prop.ou}) MERGE (m:User {objectid:prop.user}) MERGE (n)-[r:Contains {isacl:false}]->(m)"
        for user in ou['Users']:
            tx.run(user_query, props={'ou': guid, 'user': user})
            count += 1
            if count % SYNC_COUNT == 0:
                tx.sync()

def create_gpo_queries(tx, base_query, computers, objects, rel):
    """Creates the gpo queries.
    Arguments:
        tx {neo4j.Session} -- Neo4j session
        base_query {str} -- Query to base queries on.
        computers {list} -- Affected computers
        objects {list} -- Objects to apply the gpos
        rel {str} -- Name
    """
    count = 0
    for obj in objects:
        member = obj['Name']
        admin_type = obj['Type']
        query = base_query.format(admin_type, rel)
        for computer in computers:
            tx.run(query, props={"comp": computer, "member": member})
            count += 1
            if count % SYNC_COUNT == 0:
                tx.sync()

def parse_gpo_admin(tx, gpo_admin):
    """Parses a GPO admin

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        gpo_admin {dict} -- Single gpo admin object
    """
    base_query = "UNWIND {{props}} AS prop MERGE (n:{} {{objectid:prop.member}}) MERGE (m:Computer {{objectid:prop.comp}}) MERGE (n)-[r:{} {{isacl:false}}]->(m)"

    computers = []
    if 'AffectedComputers' in gpo_admin and gpo_admin['AffectedComputers'] is not None:
        computers = gpo_admin['AffectedComputers']

    if 'LocalAdmins' in gpo_admin and gpo_admin['LocalAdmins'] is not None:
        create_gpo_queries(tx, base_query, computers, gpo_admin['LocalAdmins'], "AdminTo")

    if 'RemoteDesktopUsers' in gpo_admin and gpo_admin['RemoteDesktopUsers'] is not None:
        create_gpo_queries(tx, base_query, computers, gpo_admin['RemoteDesktopUsers'], "CanRDP")

    if 'DcomUsers' in gpo_admin and gpo_admin['DcomUsers'] is not None:
        create_gpo_queries(tx, base_query, computers, gpo_admin['DcomUsers'], "ExecuteDCOM")


def parse_gpo(tx, gpo):
    """Parses a single GPO.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        gpo {dict} -- Single gpo object.
    """
    guid = gpo["ObjectIdentifier"]
    properties = gpo["Properties"]

    query = "UNWIND {props} AS prop MERGE (n:GPO {objectid:prop.guid}) SET n.guid=prop.guid, n+=prop.map"
    tx.run(query, props={'guid': guid, 'map': properties})

    if "Aces" in gpo and gpo["Aces"] is not None:
        process_ace_list(tx, gpo["Aces"], guid, "GPO")


def parse_computer(tx, computer):
    """Parse a computer object.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        computer {dict} -- Single computer object.
    """
    objectid = computer['ObjectIdentifier']

    # Properties
    property_query = ""
    props = {'map': computer['Properties'], 'objectid': objectid}
    if computer['PrimaryGroupSid'] is None:
        property_query = "UNWIND {props} AS prop MERGE (n:Computer {objectid:prop.objectid}) SET n += prop.map"
    else:
        props['pg'] = computer['PrimaryGroupSid']
        property_query = "UNWIND {props} AS prop MERGE (n:Computer {objectid:prop.objectid}) MERGE (m:Group {objectid:prop.pg}) MERGE (n)-[r:MemberOf {isacl:false}]->(m) SET n += prop.map"

    tx.run(property_query, props=props)
    count = 0
    # Delegate query
    if computer['AllowedToDelegate'] is not None:
        delegate_query = "UNWIND {props} AS prop MERGE (n:Computer {objectid: prop.objectid}) MERGE (m:Computer {objectid: prop.comp}) MERGE (n)-[r:AllowedToDelegate {isacl:false}]->(m)"
        props = []
        for x in computer['AllowedToDelegate']:
            props.append({'objectid': objectid, 'comp': x})
        tx.run(delegate_query, props=props)
        count += 1
        if count % SYNC_COUNT == 0:
            tx.sync()
    
    #Sessions
    for session in computer['Sessions']:
        parse_session(tx, session)

    # Localadmins, rdpers, dcom
    query = "UNWIND {{props}} AS prop MERGE (n:Computer {{objectid: prop.objectid}}) MERGE (m:{} {{objectid:prop.target}}) MERGE (m)-[r:{} {{isacl: false}}]->(n)"

    # DCOM
    create_computer_query(tx, computer, query, 'LocalAdmins', 'AdminTo')

    # Local Admins
    create_computer_query(tx, computer, query, 'DcomUsers', 'ExecuteDCOM')

    # RDP
    create_computer_query(tx, computer, query, 'RemoteDesktopUsers', 'CanRDP')

    # ACEs
    if 'Aces' in computer and computer['Aces'] is not None:
        process_ace_list(tx, computer['Aces'], objectid, "Computer")


def parse_user(tx, user):
    """Parse a user object.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        user {dict} -- Single user object from the bloodhound json.
    """

    uid = user['ObjectIdentifier']
    property_query = ''
    props = {'map': user['Properties'], 'uid': uid}
    if user['PrimaryGroupSid'] is None:
        property_query = "UNWIND {props} AS prop MERGE (n:User {objectid:prop.uid}) SET n += prop.map"
    else:
        props['pg'] = user['PrimaryGroupSid']
        property_query = "UNWIND {props} AS prop MERGE (n:User {objectid:prop.uid}) MERGE (m:Group {objectid:prop.pg}) MERGE (n)-[r:MemberOf {isacl:false}]->(m) SET n += prop.map"

    tx.run(property_query, props=props)
    count = 0
    # Delegation
    if 'AllowedToDelegate' in user and user['AllowedToDelegate'] is not None:
        delegate_query = "UNWIND {props} AS prop MERGE (n:User {objectid: prop.uid}) MERGE (m:Computer {object: prop.comp}) MERGE (n)-[r:AllowedToDelegate {isacl: false}]->(m)"
        props = []
        for x in user['AllowedToDelegate']:
            props.append({'uid': uid, 'comp': x})
        tx.run(delegate_query, props=props)
        count += 1
        if count % SYNC_COUNT == 0:
            tx.sync()

    # ACEs:
    if 'Aces' in user and user['Aces'] is not None:
        process_ace_list(tx, user['Aces'], uid, "User")


def parse_group(tx, group):
    """Parse a group object.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        group {dict} -- Single group object from the bloodhound json.
    """
    count = 0
    gid = group['ObjectIdentifier']
    properties = group['Properties']

    property_query = "UNWIND {props} AS prop MERGE (n:Group {objectid:prop.gid}) SET n += prop.map"

    tx.run(property_query, props={'map': properties, 'gid': gid})

    query = "UNWIND {{props}} AS prop MERGE (n:Group {{objectid: prop.gid}}) MERGE (m:{} {{objectid:prop.mid}}) MERGE (m)-[r:MemberOf {{isacl:false}}]->(n)"

    for member in group['Members']:
        mid = member['MemberId']
        mtype = member['MemberType']
        statement = query.format(mtype.title())
        tx.run(statement, props={'gid': gid, 'mid': mid})
        count += 1
        if count % SYNC_COUNT == 0:
            tx.sync()

    # Aces
    if 'Aces' in group and group['Aces'] is not None:
        process_ace_list(tx, group['Aces'], gid, "Group")


def parse_domain(tx, domain):
    """Parse a domain object.

    Arguments:
        tx {neo4j.Session} -- Neo4j session
        domain {dict} -- Single domain object from the bloodhound json.
    """

    did = domain['ObjectIdentifier']
    # Properties
    query = "UNWIND {props} AS prop MERGE (n:Domain {objectid:prop.did}) SET n += prop.map"
    tx.run(query, props={'map': domain['Properties'], 'did': did})

    # Links
    if 'Links' in domain and domain['Links'] is not None:
        links_query = "UNWIND {props} as prop MERGE (n:Domain {objectid:prop.did}) MERGE (m:GPO {objectid:prop.gpo}) MERGE (m)-[r:GpLink {enforced:prop.enforced, isacl:false}]->(n)"
        for link in domain['Links']:
            enforced = link['IsEnforced']
            target = link['Guid']
            tx.run(links_query, props={'did': did, 'gpo': target, 'enforced': enforced})

    # Trusts
    trusts_query = "UNWIND {props} AS prop MERGE (n:Domain {objectid: prop.a}) MERGE (m:Domain {objectid: prop.b}) MERGE (n)-[:TrustedBy {trusttype : prop.trusttype, transitive: prop.transitive, isacl:false}]->(m)"
    if 'Trusts' in domain and domain['Trusts'] is not None:
        for trust in domain['Trusts']:
            target = trust['TargetName']
            transitive = trust['IsTransitive']
            direction = trust['TrustDirection']
            trust_type = trust['TrustType']
            tx.run(trusts_query, props={'a': did, 'b': target, 'transitive': transitive, 'direction': direction, 'trusttype': trust_type})
            if direction == 2:
                tx.run(trusts_query, props={'a': target, 'b': did, 'transitive': transitive, 'direction': direction, 'trusttype': trust_type})

    count = 0
    # Child OUs
    if 'ChildOus' in domain and domain['ChildOus'] is not None:
        childous_query = "UNWIND {props} AS prop MERGE (n:Domain {objectid:prop.did}) MERGE (m:OU {objectid:prop.guid}) MERGE (n)-[r:Contains {isacl:false}]->(m)"
        for childou in domain['ChildOus']:
            tx.run(childous_query, props={'did': did, 'guid': childou})
            count += 1
            if count % SYNC_COUNT == 0:
                tx.sync()

    # Computers
    if 'Computers' in domain and domain['Computers'] is not None:
        computers_query = "UNWIND {props} AS prop MERGE (n:Domain {objectid:prop.did}) MERGE (m:Computer {objectid:prop.comp}) MERGE (n)-[r:Contains {isacl:false}]->(m)"
        for computer in domain["Computers"]:
            tx.run(computers_query, props={'did': did, 'comp': computer})
            count += 1
            if count % SYNC_COUNT == 0:
                tx.sync()

    # Users
    if 'Users' in domain and domain['Users'] is not None:
        users_query = "UNWIND {props} AS prop MERGE (n:Domain {objectid:prop.did}) MERGE (m:User {objectid:prop.user}) MERGE (n)-[r:Contains {isacl:false}]->(m)"
        for user in domain['Users']:
            tx.run(users_query, props={'did': did, 'user': user})
            count += 1
            if count % SYNC_COUNT == 0:
                tx.sync()

    # ACEs
    if 'Aces' in domain and domain['Aces'] is not None:
        process_ace_list(tx, domain['Aces'], did, "Domain")

def parse_session(tx, session):
    """Parse session.

    Arguments:
        tx {ses} -- [description]
        session {dict} -- dict object holding the information
    """
    query = "UNWIND {props} AS prop MERGE (n:User {objectid:prop.user}) MERGE (m:Computer {objectid:prop.comp}) MERGE (m)-[r:HasSession {isacl:false}]->(n)"
    name = session['UserId']
    comp = session['ComputerId']
    tx.run(query, props={'comp': comp, 'user': name})

def chunks(l, n):
    """Creates chunks from a list.
    From: https://stackoverflow.com/a/312464

    Arguments:
        l {list} -- List to chunk
        n {int} -- Size of the chunks.
    """

    for i in range(0, len(l), n):
        yield l[i:i + n]


def parse_file(filename, driver):
    """Parse a bloodhound file.

    Arguments:
        filename {str} -- filename to parse.
        driver {neo4j.GraphDatabase} -- driver to connect to neo4j.
    """
    logging.info("Parsing bloodhound file: %s", filename)

    with codecs.open(filename, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    obj_type = data['meta']['type']
    total = data['meta']['count']

    parsing_map = {'computers': parse_computer, 'users': parse_user, 'groups': parse_group, 'domains': parse_domain, 'sessions': parse_session, 'gpos': parse_gpo, 'ous': parse_ou, 'gpoadmins': parse_gpo_admin, 'gpomembers': parse_gpo_admin}

    # Split the data into chunks, fixing some bugs with memory usage.
    data_chunks = chunks(data[obj_type], 1000)
    count = 0

    parse_function = None
    try:
        parse_function = parsing_map[obj_type]
    except KeyError:
        logging.error("Parsing function for object type: %s was not found.", obj_type)
        return

    for chunk in data_chunks:
        # Create a new session per chunk.
        with driver.session() as session:
            for entry in chunk:
                count += 1
                session.write_transaction(parse_function, entry)

        logging.debug("%s/%s", count, total)

    logging.info("Completed file: %s", filename)
