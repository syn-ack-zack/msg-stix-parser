from tempfile import gettempdir
import ldap3
from os.path import join

test_server = 'win1.hyperv'
test_server_type = 'AD'
test_domain_name = 'FOREST.LAB'  # Active Directory Domain name
test_root_partition = 'DC=' + ',DC='.join(test_domain_name.split('.'))  # partition to use in DirSync
test_base = 'OU=test,' + test_root_partition  # base context where test objects are created
test_moved = 'ou=moved,OU=test,' + test_root_partition  # base context where objects are moved in ModifyDN operations
test_name_attr = 'cn'  # naming attribute for test objects
test_int_attr = 'logonCount'
test_server_context = ''  # used in novell eDirectory extended operations
test_server_edir_name = ''  # used in novell eDirectory extended operations
test_user = 'CN=Administrator,CN=Users,' + test_root_partition  # the user that performs the tests
test_password = 'Rc7777pfop'  # user password
test_secondary_user = 'CN=testLAB,CN=Users,' + test_root_partition
test_secondary_password = 'Rc999pfop'  # user password
test_sasl_user = 'CN=testLAB,CN=Users,' + test_root_partition
test_sasl_password = 'Rc999pfop'
test_sasl_user_dn = 'cn=testLAB,o=resources'
test_sasl_secondary_user = 'CN=testLAB,CN=Users,' + test_root_partition
test_sasl_secondary_password = 'Rc999pfop'
test_sasl_secondary_user_dn = 'cn=testSASL,o=services'
test_sasl_realm = None
test_ca_cert_file = 'local-forest-lab-ca.pem'
test_user_cert_file = ''  # 'local-forest-lab-administrator-cert.pem'
test_user_key_file = ''  # 'local-forest-lab-administrator-key.pem'
test_ntlm_user = test_domain_name.split('.')[0] + '\\Administrator'
test_ntlm_password = 'Rc7777pfop'
test_logging_filename = join(gettempdir(), 'ldap3.log')
test_valid_names = ['192.168.137.108', '192.168.137.109', 'WIN1.' + test_domain_name, 'WIN2.' + test_domain_name]

def get_operation_result(connection, operation_result):
    if not connection.strategy.sync:
        _, result = connection.get_response(operation_result)
    else:
        result = connection.result

    return result


def generate_dn(base, batch_id, name):
    return test_name_attr + '=' + batch_id + name + ',' + base


def add_user(connection, batch_id, username, password=None, attributes=None):
    if password is None:
        password = 'Rc2597pfop'

    if attributes is None:
        attributes = dict()

    attributes.update({'objectClass': ['person', 'user', 'organizationalPerson', 'top', 'inetOrgPerson'],
                       'sn': username,
                       'sAMAccountName': (batch_id[1: -1] + username)[-20:],  # 20 is the maximum user name length in AD
                       'userPrincipalName': (batch_id[1: -1] + username)[-20:] + '@' + test_domain_name,
                       'displayName': (batch_id[1: -1] + username)[-20:],
                       'unicodePwd': ('"%s"' % password).encode('utf-16-le'),
                       'userAccountControl': 512})

    dn = generate_dn(test_base, batch_id, username)
    operation_result = connection.add(dn, None, attributes)
    result = get_operation_result(connection, operation_result)
    if not result['description'] == 'success':
        raise Exception('unable to create user ' + dn + ': ' + str(result))

    return dn, result
