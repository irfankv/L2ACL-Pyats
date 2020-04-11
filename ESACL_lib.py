import re

def memory_start(uut,rtr_int_list,RPlist):
    """ Here we will start the Memory on LC and RP location"""

    for intf in rtr_int_list :
        LC = re.search(r'(\d/\d)[0-9/]+', intf).group(1)
    for rp in RPlist :
        if rp is not None:
            #logger.info("===== Memory SUmmary before the trigger at RPs level ==== ")
            mem = "show memory compare start location %s" % (rp + "/CPU0")
            uut.execute(mem)
        else :
            return False
    return True




def basic_acls_format():
    basic_acls = dict()
    basic_acls['format-1'] = dict()
    basic_acls['format-1']['ace_list'] = '''
    10 deny 00ff.eedd.0010 ff00.0000.00ff 0000.0100.0001 0000.0000.ffff
    20 permit host 000a.000b.000c host 00aa.ab99.1122 cos 1 dei
    30 deny host 000a.000b.000c host 00aa.dc11.ba99 cos 7 dei''' #change this vlan to vlan range vlan 10-20 when vlan range for ES ACL is supported
    # Change ACE 20 and 10 to "20 permit host a.b.c host 00aa.ab99.1122 vlan 10 cos 1 dei" VLAN SDK BUG is resolved and
    #10 deny 00ff.eedd.0010 ff00.0000.00ff 0000.0100.0001 0000.0000.ffff vlan 100
    #30 deny host 000a.000b.000c host 00aa.dc11.ba99 vlan 20 cos 7 dei
    basic_acls['format-1']['stream'] = dict()
    basic_acls['format-1']['stream'][1] = dict()
    basic_acls['format-1']['stream'][1]['params'] = {'vlan_id': '100', 'mac_src': '00:ff:ee:dd:00:10','mac_dst': '00:00:01:00:00:01','vlan_user_priority': '1', 'vlan_cfi': '1'}
    basic_acls['format-1']['stream'][1]['seq'] = 10
    basic_acls['format-1']['stream'][2] = dict()
    basic_acls['format-1']['stream'][2]['params'] = {'vlan_id': '10','mac_src': '00:0a:00:0b:00:0c', 'mac_dst': '00:aa:ab:99:11:22','vlan_user_priority': '1', 'vlan_cfi': '1',}
    basic_acls['format-1']['stream'][2]['seq'] = 20
    basic_acls['format-1']['stream'][3] = dict()

    basic_acls['format-1']['stream'][3]['params'] = {'vlan_id': '20','mac_src': '00:0a:00:0b:00:0c', 'mac_dst': '00:aa:dc:11:ba:99','vlan_user_priority': '7', 'vlan_cfi': '1'}
    basic_acls['format-1']['stream'][3]['seq'] = 30
    basic_acls['format-1']['stream'][4] = dict()
    basic_acls['format-1']['stream'][4]['seq'] = 'implicit'
    basic_acls['format-1']['stream'][4]['params'] = {'vlan_id': '110', 'mac_src': '00:ff:ee:dd:00:12'}
    basic_acls['format-2'] = dict()
    basic_acls['format-2']['ace_list'] = '''
    10 permit 00ff.eedd.0010 ff00.0000.00ff 0011.ab10.cdef ffff.0000.ff00 cos 7 dei
    20 deny host eedd.0011.ff1c any  cos 1 dei
    30 permit any any cos 2'''
    #Change ACE 20 , to 20 deny host eedd.0011.ff1c any vlan 300  cos 1 dei when VLAN bug is resolved
    basic_acls['format-2']['stream'] = dict()
    basic_acls['format-2']['stream'][1] = dict()
    basic_acls['format-2']['stream'][1]['params'] = {'vlan_id': '1005', 'mac_src': '00:FF:EE:DD:00:10','mac_dst': '00:11:AB:10:CD:EF','vlan_user_priority': '7', 'vlan_cfi': '1'}
    basic_acls['format-2']['stream'][1]['seq'] = 10
    basic_acls['format-2']['stream'][2] = dict()
    basic_acls['format-2']['stream'][2]['params'] = {'vlan_id': ['300','30'],'mac_src': 'ee:dd:00:11:ff:1c', 'vlan_user_priority': ['1','0'], 'vlan_cfi': ['1','0']}
    basic_acls['format-2']['stream'][2]['seq'] = 20
    basic_acls['format-2']['stream'][3] = dict()
    basic_acls['format-2']['stream'][3]['params'] = {'vlan_id': '500', 'vlan_user_priority': '2','vlan_cfi': '0'}
    basic_acls['format-2']['stream'][3]['seq'] = 30
    basic_acls['format-2']['stream'][4] = dict()
    basic_acls['format-2']['stream'][4]['seq'] = 'implicit'
    basic_acls['format-2']['stream'][4]['params'] = {'vlan_id': '210', 'mac_src': '00:AA:FF:BB:FF:29','mac_dst': 'ff:29:ff:AA:ff:BB', 'vlan_user_priority': '4','vlan_cfi': '0'}

    basic_acls['format-3'] = dict()
    basic_acls['format-3']['ace_list'] = '''
    10 deny any host 0011.ab10.cdef
    20 permit any host 000a.000b.000c cos 2 dei
    30 permit any host 000a.000b.000c cos 5 dei'''
    #change ACE 10 to 10 deny any host 0011.ab10.cdef vlan 2000 when VLAN bug is resolved
    basic_acls['format-3']['stream'] = dict()
    basic_acls['format-3']['stream'][1] = dict()
    basic_acls['format-3']['stream'][1]['params'] = {'vlan_id': '2000', 'mac_dst': '00:11:AB:10:CD:EF','vlan_user_priority': '2','vlan_cfi': '1'}
    basic_acls['format-3']['stream'][1]['seq'] = 10
    basic_acls['format-3']['stream'][2] = dict()
    basic_acls['format-3']['stream'][2]['params'] = {'vlan_id': '500', 'vlan_user_priority': '2', 'vlan_id_count': '1', 'vlan_cfi': '1', 'mac_dst': '00:0a:00:0b:00:0c'}
    basic_acls['format-3']['stream'][2]['seq'] = 20
    basic_acls['format-3']['stream'][3] = dict()
    basic_acls['format-3']['stream'][3]['params'] = {'vlan_id': '600', 'vlan_user_priority': '5', 'vlan_cfi': '1','mac_dst': '00:0a:00:0b:00:0c'}
    basic_acls['format-3']['stream'][3]['seq'] = 30
    basic_acls['format-3']['stream'][4] = dict()
    basic_acls['format-3']['stream'][4]['seq'] = 'implicit'
    basic_acls['format-3']['stream'][4]['params'] = {'vlan_id': '300', 'mac_dst': 'ee:dd:00:11:ff:1c','vlan_user_priority': '1', 'vlan_cfi': '1'}

    return basic_acls

def acl_edits_dic():
    acl_edits = dict()
    acl_edits['value-edit'] = dict()
    acl_edits['value-edit']['tc_name'] = "ACL edit: value change"
    acl_edits['value-edit']['direction'] = "ingress"
    acl_edits['value-edit']['stream'] = dict()
    acl_edits['value-edit']['stream'][1] = dict()
    acl_edits['value-edit']['stream'][2] = dict()
    acl_edits['value-edit']['stream'][1]['params'] = {'vlan_id': '300', 'mac_src': '00:00:00:ab:cd:ef',
                                                      'mac_dst': '00:01:00:02:00:03'}
    acl_edits['value-edit']['stream'][2]['params'] = {'mac_src': '00:00:12:ab:cd:ef', 'mac_dst': 'aa:bb:cc:dd:ee:ff'}

    acl_edits['value-edit']['acl'] = dict()
    acl_edits['value-edit']['acl'][1] = dict()
    acl_edits['value-edit']['acl'][1]['stream'] = dict()
    acl_edits['value-edit']['acl'][1]['stream'][1] = dict()
    acl_edits['value-edit']['acl'][1]['stream'][2] = dict()
    acl_edits['value-edit']['acl'][2] = dict()
    acl_edits['value-edit']['acl'][2]['stream'] = dict()
    acl_edits['value-edit']['acl'][2]['stream'][1] = dict()
    acl_edits['value-edit']['acl'][2]['stream'][2] = dict()

    acl_edits['value-edit']['acl'][1]['ace_list'] = """
    10 permit host 0000.00ab.cdef host 0001.0002.0003
    20 deny  host 0000.12ab.cdef any
    """
    acl_edits['value-edit']['acl'][1]['stream'][1]['seq'] = 10
    acl_edits['value-edit']['acl'][1]['stream'][2]['seq'] = 20

    acl_edits['value-edit']['acl'][2]['ace_list'] = """
    10 permit host 0000.00ab.cdef host 0001.0002.0004
    """
    acl_edits['value-edit']['acl'][2]['stream'][1]['seq'] = 20
    acl_edits['value-edit']['acl'][2]['stream'][2]['seq'] = 'implicit'

    acl_edits['field-edit-no-format-change'] = dict()
    acl_edits['field-edit-no-format-change']['tc_name'] = "ACL edit: field edit,no format change"
    acl_edits['field-edit-no-format-change']['direction'] = "ingress"
    acl_edits['field-edit-no-format-change']['stream'] = dict()
    acl_edits['field-edit-no-format-change']['stream'][1] = dict()
    acl_edits['field-edit-no-format-change']['stream'][1]['params'] = {'vlan_id': '200', 'mac_src': '00:00:00:ab:cd:ef',
                                                                       'mac_dst': '12:34:56:78:90:ab'}

    acl_edits['field-edit-no-format-change']['stream'][2] = dict()
    acl_edits['field-edit-no-format-change']['stream'][2]['params'] = {'mac_src': '00:00:00:ab:cc:cc',
                                                                       'vlan_user_priority': '2'}

    acl_edits['field-edit-no-format-change']['acl'] = dict()
    acl_edits['field-edit-no-format-change']['acl'][1] = dict()
    acl_edits['field-edit-no-format-change']['acl'][1]['ace_list'] = """
    10 deny host 0000.00ab.cdef any
    20 permit host 0000.00ab.cccc any
    """
    # Change ACE to 10 deny host 0000.00ab.cdef any vlan 200 when VLAN SDK bug is resolve
    acl_edits['field-edit-no-format-change']['acl'][1]['stream'] = dict()

    acl_edits['field-edit-no-format-change']['acl'][1]['stream'][1] = dict()
    acl_edits['field-edit-no-format-change']['acl'][1]['stream'][1]['seq'] = 10

    acl_edits['field-edit-no-format-change']['acl'][1]['stream'][2] = dict()
    acl_edits['field-edit-no-format-change']['acl'][1]['stream'][2]['seq'] = 20

    acl_edits['field-edit-no-format-change']['acl'][2] = dict()
    acl_edits['field-edit-no-format-change']['acl'][2]['ace_list'] = """
    20 permit host 0000.00ab.cccc any cos 4
    """
    acl_edits['field-edit-no-format-change']['acl'][2]['stream'] = dict()

    acl_edits['field-edit-no-format-change']['acl'][2]['stream'][1] = dict()
    acl_edits['field-edit-no-format-change']['acl'][2]['stream'][1]['seq'] = 10

    acl_edits['field-edit-no-format-change']['acl'][2]['stream'][2] = dict()
    acl_edits['field-edit-no-format-change']['acl'][2]['stream'][2]['seq'] = 'implicit'

    acl_edits['field-edit-format-change'] = dict()
    acl_edits['field-edit-format-change']['tc_name'] = "ACL edit: field edit,format change"
    acl_edits['field-edit-format-change']['direction'] = "ingress"
    acl_edits['field-edit-format-change']['stream'] = dict()
    acl_edits['field-edit-format-change']['stream'][1] = dict()
    acl_edits['field-edit-format-change']['stream'][1]['params'] = {'vlan_id': '500', 'mac_src': '12:34:56:78:90:ab',
                                                                    'mac_dst': '00:00:00:ab:cd:ef'}

    acl_edits['field-edit-format-change']['stream'][2] = dict()
    acl_edits['field-edit-format-change']['stream'][2]['params'] = {'mac_src': '12:34:56:78:90:ab','mac_dst': '00:12:34:ab:cd:ef',
                                                                    'vlan_user_priority': '2'}

    acl_edits['field-edit-format-change']['acl'] = dict()
    acl_edits['field-edit-format-change']['acl'][1] = dict()
    acl_edits['field-edit-format-change']['acl'][1]['ace_list'] = """
    10 deny any host 0000.00ab.cdef
    20 permit any any
    """
    # Chane the ACE 10 to 10 deny any host 0000.00ab.cdef vlan 500 when VLAN is SDK is resolved
    acl_edits['field-edit-format-change']['acl'][1]['stream'] = dict()

    acl_edits['field-edit-format-change']['acl'][1]['stream'][1] = dict()
    acl_edits['field-edit-format-change']['acl'][1]['stream'][1]['seq'] = 10

    acl_edits['field-edit-format-change']['acl'][1]['stream'][2] = dict()
    acl_edits['field-edit-format-change']['acl'][1]['stream'][2]['seq'] = 20

    acl_edits['field-edit-format-change']['acl'][2] = dict()
    acl_edits['field-edit-format-change']['acl'][2]['ace_list'] = """
    10 deny host 1234.5678.90ab host 0000.00ab.cdef
    """
    # Chane the ACE 10 to 10 deny host 1234.5678.90ab host 0000.00ab.cdef vlan 500 when VLAN is SDK is resolved
    acl_edits['field-edit-format-change']['acl'][2]['stream'] = dict()

    acl_edits['field-edit-format-change']['acl'][2]['stream'][1] = dict()
    acl_edits['field-edit-format-change']['acl'][2]['stream'][1]['seq'] = 10

    acl_edits['field-edit-format-change']['acl'][2]['stream'][2] = dict()
    acl_edits['field-edit-format-change']['acl'][2]['stream'][2]['seq'] = 20

    acl_edits['ace-insert-no-format-change'] = dict()
    acl_edits['ace-insert-no-format-change']['tc_name'] = "ACL edit: ace insert,no format change"
    acl_edits['ace-insert-no-format-change']['direction'] = "ingress"
    acl_edits['ace-insert-no-format-change']['stream'] = dict()
    acl_edits['ace-insert-no-format-change']['stream'][1] = dict()
    acl_edits['ace-insert-no-format-change']['stream'][1]['params'] = {'vlan_id': '500', 'mac_src': '10:00:22:22:33:33',
                                                                       'mac_dst': '00:00:00:ab:cd:ef'}

    acl_edits['ace-insert-no-format-change']['stream'][2] = dict()
    acl_edits['ace-insert-no-format-change']['stream'][2]['params'] = {'mac_src': '00:00:00:ab:cc:cc',
                                                                       'vlan_user_priority': '2'}

    acl_edits['ace-insert-no-format-change']['stream'][3] = dict()
    acl_edits['ace-insert-no-format-change']['stream'][3]['params'] = {'vlan_id': '500', 'mac_src': '12:34:56:78:90:ab',
                                                                       'mac_dst': '00:00:00:ab:cd:ef'}

    acl_edits['ace-insert-no-format-change']['acl'] = dict()
    acl_edits['ace-insert-no-format-change']['acl'][1] = dict()
    acl_edits['ace-insert-no-format-change']['acl'][1]['ace_list'] = """
    10 deny host 1000.2222.3333 host 0000.00ab.cdef
    20 permit any any
    """
    acl_edits['ace-insert-no-format-change']['acl'][1]['stream'] = dict()

    acl_edits['ace-insert-no-format-change']['acl'][1]['stream'][1] = dict()
    acl_edits['ace-insert-no-format-change']['acl'][1]['stream'][1]['seq'] = 10

    acl_edits['ace-insert-no-format-change']['acl'][1]['stream'][2] = dict()
    acl_edits['ace-insert-no-format-change']['acl'][1]['stream'][2]['seq'] = 20

    acl_edits['ace-insert-no-format-change']['acl'][1]['stream'][3] = dict()
    acl_edits['ace-insert-no-format-change']['acl'][1]['stream'][3]['seq'] = 20

    acl_edits['ace-insert-no-format-change']['acl'][2] = dict()
    acl_edits['ace-insert-no-format-change']['acl'][2]['ace_list'] = """
    15 permit host 1234.5678.90ab host 0000.00ab.cdef
    """
    acl_edits['ace-insert-no-format-change']['acl'][2]['stream'] = dict()

    acl_edits['ace-insert-no-format-change']['acl'][2]['stream'][1] = dict()
    acl_edits['ace-insert-no-format-change']['acl'][2]['stream'][1]['seq'] = 10

    acl_edits['ace-insert-no-format-change']['acl'][2]['stream'][2] = dict()
    acl_edits['ace-insert-no-format-change']['acl'][2]['stream'][2]['seq'] = 20
    acl_edits['ace-insert-no-format-change']['acl'][2]['stream'][3] = dict()
    acl_edits['ace-insert-no-format-change']['acl'][2]['stream'][3]['seq'] = 15

    acl_edits['ace-insert-format-change'] = dict()
    acl_edits['ace-insert-format-change']['tc_name'] = "ACL edit: ace insert,format change"
    acl_edits['ace-insert-format-change']['direction'] = "ingress"
    acl_edits['ace-insert-format-change']['stream'] = dict()
    acl_edits['ace-insert-format-change']['stream'][1] = dict()
    acl_edits['ace-insert-format-change']['stream'][1]['params'] = {'vlan_id': '500', 'mac_src': '10:00:22:22:33:33',
                                                                    'mac_dst': '00:00:00:ab:cd:ef'}

    acl_edits['ace-insert-format-change']['stream'][2] = dict()
    acl_edits['ace-insert-format-change']['stream'][2]['params'] = {'mac_src': '00:00:00:ab:cc:cc',
                                                                    'vlan_user_priority': '2'}

    acl_edits['ace-insert-format-change']['stream'][3] = dict()
    acl_edits['ace-insert-format-change']['stream'][3]['params'] = {'vlan_id': ['500', '500'],
                                                                    'mac_src': '12:34:56:78:90:ab',
                                                                    'mac_dst': '00:00:00:ab:cd:ef'}

    acl_edits['ace-insert-format-change']['acl'] = dict()
    acl_edits['ace-insert-format-change']['acl'][1] = dict()
    acl_edits['ace-insert-format-change']['acl'][1]['ace_list'] = """
    10 permit host 1000.2222.3333 host 0000.00ab.cdef
    20 permit any any
    """
    acl_edits['ace-insert-format-change']['acl'][1]['stream'] = dict()

    acl_edits['ace-insert-format-change']['acl'][1]['stream'][1] = dict()
    acl_edits['ace-insert-format-change']['acl'][1]['stream'][1]['seq'] = 10

    acl_edits['ace-insert-format-change']['acl'][1]['stream'][2] = dict()
    acl_edits['ace-insert-format-change']['acl'][1]['stream'][2]['seq'] = 20

    acl_edits['ace-insert-format-change']['acl'][1]['stream'][3] = dict()
    acl_edits['ace-insert-format-change']['acl'][1]['stream'][3]['seq'] = 20

    acl_edits['ace-insert-format-change']['acl'][2] = dict()
    acl_edits['ace-insert-format-change']['acl'][2]['ace_list'] = """
    5 permit host 1234.5678.90ab host 0000.00ab.cdef
    """
    # Change 5 ACE to 5 permit host 1234.5678.90ab host 0000.00ab.cdef vlan 500, after VLAN SDK bug is resolves
    acl_edits['ace-insert-format-change']['acl'][2]['stream'] = dict()

    acl_edits['ace-insert-format-change']['acl'][2]['stream'][1] = dict()
    acl_edits['ace-insert-format-change']['acl'][2]['stream'][1]['seq'] = 10

    acl_edits['ace-insert-format-change']['acl'][2]['stream'][2] = dict()
    acl_edits['ace-insert-format-change']['acl'][2]['stream'][2]['seq'] = 20
    acl_edits['ace-insert-format-change']['acl'][2]['stream'][3] = dict()
    acl_edits['ace-insert-format-change']['acl'][2]['stream'][3]['seq'] = 5

    acl_edits['ace-delete'] = dict()
    acl_edits['ace-delete']['tc_name'] = "ACL edit: ace delete"
    acl_edits['ace-delete']['direction'] = "ingress"
    acl_edits['ace-delete']['stream'] = dict()
    acl_edits['ace-delete']['stream'][1] = dict()
    acl_edits['ace-delete']['stream'][1]['params'] = {'mac_src': '10:00:22:22:33:33', 'mac_dst': '00:00:00:ab:cd:ef','vlan_user_priority': '1'}

    acl_edits['ace-delete']['stream'][2] = dict()
    acl_edits['ace-delete']['stream'][2]['params'] = {'vlan_id': ['500', '500'], 'mac_src': '12:34:56:78:90:ab',
                                                      'mac_dst': '00:00:00:AB:CD:01','vlan_user_priority': '2'}
    acl_edits['ace-delete']['stream'][3] = dict()
    acl_edits['ace-delete']['stream'][3]['params'] = {'vlan_id': '500', 'mac_src': '12:34:56:78:90:ab',
                                                      'mac_dst': '00:00:00:ab:cd:ef'}

    acl_edits['ace-delete']['acl'] = dict()
    acl_edits['ace-delete']['acl'][1] = dict()
    acl_edits['ace-delete']['acl'][1]['ace_list'] = """
    5 deny host 1234.5678.90ab host 0000.00ab.cdef
    10 permit host 1000.2222.3333 host 0000.00ab.cdef
    20 permit any any cos 2
    """
    # Change ACE 5  to 5 deny host 1234.5678.90ab host 0000.00ab.cdef vlan 500
    acl_edits['ace-delete']['acl'][1]['stream'] = dict()

    acl_edits['ace-delete']['acl'][1]['stream'][1] = dict()
    acl_edits['ace-delete']['acl'][1]['stream'][1]['seq'] = 10

    acl_edits['ace-delete']['acl'][1]['stream'][2] = dict()
    acl_edits['ace-delete']['acl'][1]['stream'][2]['seq'] = 20

    acl_edits['ace-delete']['acl'][1]['stream'][3] = dict()
    acl_edits['ace-delete']['acl'][1]['stream'][3]['seq'] = 5

    acl_edits['ace-delete']['acl'][2] = dict()
    acl_edits['ace-delete']['acl'][2]['ace_list'] = """
    no 5
    """
    acl_edits['ace-delete']['acl'][2]['stream'] = dict()

    acl_edits['ace-delete']['acl'][2]['stream'][1] = dict()
    acl_edits['ace-delete']['acl'][2]['stream'][1]['seq'] = 10

    acl_edits['ace-delete']['acl'][2]['stream'][2] = dict()
    acl_edits['ace-delete']['acl'][2]['stream'][2]['seq'] = 20
    acl_edits['ace-delete']['acl'][2]['stream'][3] = dict()
    acl_edits['ace-delete']['acl'][2]['stream'][3]['seq'] = 'implicit'

    acl_edits['multiple-ace-edits'] = dict()
    acl_edits['multiple-ace-edits']['tc_name'] = "ACL edit: multiple edits"
    acl_edits['multiple-ace-edits']['direction'] = "ingress"
    acl_edits['multiple-ace-edits']['stream'] = dict()
    acl_edits['multiple-ace-edits']['stream'][1] = dict()
    acl_edits['multiple-ace-edits']['stream'][1]['params'] = {'vlan_id': '100', 'mac_src': '10:00:22:22:33:33',
                                                              'mac_dst': '00:00:00:ab:cd:ef', 'vlan_user_priority': '5'}

    acl_edits['multiple-ace-edits']['stream'][2] = dict()
    acl_edits['multiple-ace-edits']['stream'][2]['params'] = {'mac_src': 'aa:aa:bb:bb:cc:cc', 'vlan_user_priority': '2'}

    acl_edits['multiple-ace-edits']['stream'][3] = dict()
    acl_edits['multiple-ace-edits']['stream'][3]['params'] = {'vlan_id': '500', 'vlan_cfi': '1',
                                                              'mac_src': '12:34:56:78:90:ab',
                                                              'mac_dst': '00:00:00:ab:cd:ef'}

    acl_edits['multiple-ace-edits']['stream'][4] = dict()
    acl_edits['multiple-ace-edits']['stream'][4]['params'] = {'vlan_id': '1500', 'mac_src': '12:34:56:78:90:ab',
                                                              'mac_dst': '99:99:99:99:99:99'}

    acl_edits['multiple-ace-edits']['stream'][5] = dict()
    acl_edits['multiple-ace-edits']['stream'][5]['params'] = {'mac_src': '12:34:56:78:90:ab',
                                                              'mac_dst': 'bb:00:00:ab:cd:ef'}

    acl_edits['multiple-ace-edits']['acl'] = dict()
    acl_edits['multiple-ace-edits']['acl'][1] = dict()
    acl_edits['multiple-ace-edits']['acl'][1]['ace_list'] = """
    10 permit host 1000.2222.3333 host 0000.00ab.cdef cos 5
    20 deny host aaaa.bbbb.cccc any
    30 permit any host 0000.00ab.cdef dei
    40 deny any host 9999.9999.9999
    50 permit any any
    """
    acl_edits['multiple-ace-edits']['acl'][1]['stream'] = dict()

    acl_edits['multiple-ace-edits']['acl'][1]['stream'][1] = dict()
    acl_edits['multiple-ace-edits']['acl'][1]['stream'][1]['seq'] = 10

    acl_edits['multiple-ace-edits']['acl'][1]['stream'][2] = dict()
    acl_edits['multiple-ace-edits']['acl'][1]['stream'][2]['seq'] = 20

    acl_edits['multiple-ace-edits']['acl'][1]['stream'][3] = dict()
    acl_edits['multiple-ace-edits']['acl'][1]['stream'][3]['seq'] = 30

    acl_edits['multiple-ace-edits']['acl'][1]['stream'][4] = dict()
    acl_edits['multiple-ace-edits']['acl'][1]['stream'][4]['seq'] = 40

    acl_edits['multiple-ace-edits']['acl'][1]['stream'][5] = dict()
    acl_edits['multiple-ace-edits']['acl'][1]['stream'][5]['seq'] = 50

    acl_edits['multiple-ace-edits']['acl'][2] = dict()
    acl_edits['multiple-ace-edits']['acl'][2]['ace_list'] = """
    10 deny host 1000.2222.3333 host 0000.00ab.cdef
    no 20
    30 permit host 1234.5678.90ab host 0000.00ab.cdef dei
    35 deny host aaaa.bbbb.cccc any
    """
    acl_edits['multiple-ace-edits']['acl'][2]['stream'] = dict()

    acl_edits['multiple-ace-edits']['acl'][2]['stream'][1] = dict()
    acl_edits['multiple-ace-edits']['acl'][2]['stream'][1]['seq'] = 10

    acl_edits['multiple-ace-edits']['acl'][2]['stream'][2] = dict()
    acl_edits['multiple-ace-edits']['acl'][2]['stream'][2]['seq'] = 35
    acl_edits['multiple-ace-edits']['acl'][2]['stream'][3] = dict()
    acl_edits['multiple-ace-edits']['acl'][2]['stream'][3]['seq'] = 30

    acl_edits['multiple-ace-edits']['acl'][2]['stream'][4] = dict()
    acl_edits['multiple-ace-edits']['acl'][2]['stream'][4]['seq'] = 40

    acl_edits['multiple-ace-edits']['acl'][2]['stream'][5] = dict()
    acl_edits['multiple-ace-edits']['acl'][2]['stream'][5]['seq'] = 50

    return acl_edits

def atomic_replace_dic():
    atomic_replace = dict()
    atomic_replace['direction'] = dict()
    atomic_replace['direction'] = "ingress"
    atomic_replace['stream'] = dict()
    atomic_replace['stream'][1] = dict()
    atomic_replace['stream'][1]['params'] = {'vlan_id': '10', 'mac_src': '00:AA:00:BB:00:10','mac_dst': '00:10:00:AA:00:BB','vlan_user_priority': '0','vlan_cfi': '0'}

    atomic_replace['stream'][2] = dict()
    atomic_replace['stream'][2]['params'] = {'vlan_id': '20','mac_src': '00:AA:00:BB:00:11', 'mac_dst': '00:11:00:AA:00:BB','vlan_user_priority': '1','vlan_cfi': '1'}

    atomic_replace['stream'][3] = dict()
    atomic_replace['stream'][3]['params'] = {'vlan_id': '30', 'mac_src': '00:AA:00:BB:00:12','mac_dst': '00:12:00:AA:00:BB','vlan_user_priority': '2','vlan_cfi': '0'}

    atomic_replace['stream'][4] = dict()
    atomic_replace['stream'][4]['params'] = {'vlan_id': '40','mac_src': '00:AA:00:BB:00:13', 'mac_dst': '00:13:00:AA:00:BB','vlan_user_priority': '3','vlan_cfi': '1'}

    atomic_replace['acl'] = dict()
    atomic_replace['acl'][1]=dict()
    atomic_replace['acl'][1]['ace_list'] = """
    10 deny 00AA.00BB.0010 ff00.ff00.0000 0010.00AA.00BB ff00.0000.ffff  cos 0
    20 permit 00AA.00BB.0011 ff00.ff00.0000 0011.00AA.00BB ff00.0000.ffff  cos 1 dei
    30 deny 00AA.00BB.0012 ff00.ff00.0000 0012.00AA.00BB ff00.0000.ffff  cos 2
    40 permit 00AA.00BB.0013 ff00.ff00.0000 0013.00AA.00BB ff00.0000.ffff  cos 3 dei
    """
    #Put VLAN 10 for ACE 10, 20 for ACE 20 , 30 for ACE 30 and VLAN 40 for ACE 40, when VLAN SDK Bug is resolves.
    # VLAN from all the ACE's(10,20,30,40) to VLAN range vlan 1-4094 when VLAN range is supported

    atomic_replace['acl'][1]['stream'] = dict()

    atomic_replace['acl'][1]['stream'][1] = dict()
    atomic_replace['acl'][1]['stream'][1]['seq'] = 10

    atomic_replace['acl'][1]['stream'][2] = dict()
    atomic_replace['acl'][1]['stream'][2]['seq'] = 20

    atomic_replace['acl'][1]['stream'][3] = dict()
    atomic_replace['acl'][1]['stream'][3]['seq'] = 30

    atomic_replace['acl'][1]['stream'][4] = dict()
    atomic_replace['acl'][1]['stream'][4]['seq'] = 40

    atomic_replace['acl'][2]=dict()
    atomic_replace['acl'][2]['ace_list'] = """
    10 permit 00AA.00BB.0010 ff00.ff00.0000 0010.00AA.00BB ff00.0000.ffff  cos 0
    20 deny   00AA.00BB.0011 ff00.ff00.0000 0011.00AA.00BB ff00.0000.ffff  cos 1 dei
    30 permit 00AA.00BB.0012 ff00.ff00.0000 0012.00AA.00BB ff00.0000.ffff  cos 2
    40 deny   00AA.00BB.0013 ff00.ff00.0000 0013.00AA.00BB ff00.0000.ffff  cos 3 dei
    """
    #Put VLAN 10 for ACE 10, 20 for ACE 20 , 30 for ACE 30 and VLAN 40 for ACE 40, when VLAN SDK Bug is resolves.
    # VLAN from all the ACE's(10,20,30,40) to VLAN range vlan 1-4094 when VLAN range is supported


    atomic_replace['acl'][2]['stream'] = dict()

    atomic_replace['acl'][2]['stream'][1] = dict()
    atomic_replace['acl'][2]['stream'][1]['seq'] = 10

    atomic_replace['acl'][2]['stream'][2] = dict()
    atomic_replace['acl'][2]['stream'][2]['seq'] = 20
    atomic_replace['acl'][2]['stream'][3] = dict()
    atomic_replace['acl'][2]['stream'][3]['seq'] = 30

    atomic_replace['acl'][2]['stream'][4] = dict()
    atomic_replace['acl'][2]['stream'][4]['seq'] = 40

    return atomic_replace

def acl_double_tag_dic() :
    acl_double_tag = dict()
    acl_double_tag['dot1q_dot1q'] = dict()
    acl_double_tag['dot1q_dot1q']['tc_name'] = "ACL with double tag dot1q"
    acl_double_tag['dot1q_dot1q']['direction'] = "ingress"
    acl_double_tag['dot1q_dot1q']['stream'] = dict()
    acl_double_tag['dot1q_dot1q']['stream'][1] = dict()
    acl_double_tag['dot1q_dot1q']['stream'][1]['params'] = {'vlan_id': '10', 'mac_src': '10:11:33:44:55:66',
                                                            'vlan_id_outer': '500',
                                                            'vlan_outer_tpid': 33024, 'vlan_tpid': 33024,
                                                            'vlan_outer_cfi': 1,
                                                            'vlan_outer_user_priority': 5, 'mac_dst': '00:00:00:ab:cd:ef',
                                                            'vlan_user_priority': '5'}

    acl_double_tag['dot1q_dot1q']['stream'][2] = dict()
    acl_double_tag['dot1q_dot1q']['stream'][2]['params'] = {'vlan_id': '10', 'mac_src': 'aa:aa:bb:bb:cc:cc',
                                                            'vlan_id_outer': '500',
                                                            'vlan_outer_tpid': 33024, 'vlan_tpid': 33024,
                                                            'vlan_outer_cfi': 1, 'vlan_outer_user_priority': 7,
                                                            'mac_dst': 'ab:cd:ef:11:11:11', 'vlan_user_priority': '5'}

    acl_double_tag['dot1q_dot1q']['stream'][3] = dict()
    acl_double_tag['dot1q_dot1q']['stream'][3]['params'] = {'vlan_id': '10', 'mac_src': '10:14:34:45:55:65',
                                                            'vlan_id_outer': '500',
                                                            'vlan_outer_tpid': 33024, 'vlan_tpid': 33024,
                                                            'vlan_outer_cfi': 1,
                                                            'vlan_outer_user_priority': 3, 'mac_dst': 'ab:cd:ef:00:00:00',
                                                            'vlan_user_priority': '5'}

    acl_double_tag['dot1q_dot1q']['stream'][4] = dict()
    acl_double_tag['dot1q_dot1q']['stream'][4]['params'] = {'vlan_id': '10', 'vlan_cfi': '1',
                                                            'mac_src': '10:14:34:45:55:65', 'vlan_id_outer': '500',
                                                            'vlan_outer_tpid': 33024, 'vlan_tpid': 33024,
                                                            'vlan_outer_cfi': 0,
                                                            'vlan_outer_user_priority': 5, 'mac_dst': 'ab:cd:ef:00:00:00',
                                                            'vlan_user_priority': '3'}

    acl_double_tag['dot1q_dot1q']['acl'] = dict()
    acl_double_tag['dot1q_dot1q']['acl'][1] = dict()
    acl_double_tag['dot1q_dot1q']['encap'] = """
    encapsulation dot1q 500 second-dot1q 10
    """
    acl_double_tag['dot1q_dot1q']['acl'][1]['ace_list'] = """
    10 permit host 1011.3344.5566 host 0000.00ab.cdef cos 5 dei
    20 deny host aaaa.bbbb.cccc any cos 7 dei
    30 permit any host abcd.ef00.0000 dei cos 3
    """
    acl_double_tag['dot1q_dot1q']['acl'][1]['stream'] = dict()

    acl_double_tag['dot1q_dot1q']['acl'][1]['stream'][1] = dict()
    acl_double_tag['dot1q_dot1q']['acl'][1]['stream'][1]['seq'] = 10

    acl_double_tag['dot1q_dot1q']['acl'][1]['stream'][2] = dict()
    acl_double_tag['dot1q_dot1q']['acl'][1]['stream'][2]['seq'] = 20

    acl_double_tag['dot1q_dot1q']['acl'][1]['stream'][3] = dict()
    acl_double_tag['dot1q_dot1q']['acl'][1]['stream'][3]['seq'] = 30

    acl_double_tag['dot1q_dot1q']['acl'][1]['stream'][4] = dict()
    acl_double_tag['dot1q_dot1q']['acl'][1]['stream'][4]['seq'] = 'implicit'

    acl_double_tag['dot1ad_dot1q'] = dict()
    acl_double_tag['dot1ad_dot1q']['tc_name'] = "ACL with double tag dot1ad and secondary dot1q"
    acl_double_tag['dot1ad_dot1q']['direction'] = "ingress"
    acl_double_tag['dot1ad_dot1q']['stream'] = dict()
    acl_double_tag['dot1ad_dot1q']['stream'][1] = dict()
    acl_double_tag['dot1ad_dot1q']['stream'][1]['params'] = {'vlan_id': '10', 'mac_src': '00:00:00:ab:cd:ef',
                                                             'mac_dst': '10:00:22:22:33:33', 'vlan_id_outer': '200',
                                                             'vlan_outer_tpid': 34984, 'vlan_tpid': 33024,
                                                             'vlan_outer_cfi': 1,
                                                             'vlan_outer_user_priority': 0, 'vlan_user_priority': '5'}


    acl_double_tag['dot1ad_dot1q']['stream'][2] = dict()
    acl_double_tag['dot1ad_dot1q']['stream'][2]['params'] = {'vlan_id': '10', 'mac_dst': '10:00:22:22:33:44',
                                                             'vlan_id_outer': '200',
                                                             'vlan_outer_tpid': 34984, 'vlan_tpid': 33024,
                                                             'vlan_outer_cfi': 1, 'vlan_outer_user_priority': 2,
                                                             'mac_src': '00:00:01:1a:cd:ef', 'vlan_user_priority': '5'}

    acl_double_tag['dot1ad_dot1q']['stream'][3] = dict()
    acl_double_tag['dot1ad_dot1q']['stream'][3]['params'] = {'vlan_id': '10', 'mac_src': '00:00:00:ab:cd:11',
                                                             'vlan_id_outer': '200',
                                                             'vlan_outer_tpid': 34984, 'vlan_tpid': 33024,
                                                             'vlan_outer_cfi': 0,
                                                             'vlan_outer_user_priority': 4, 'mac_dst': '10:00:22:22:33:10',
                                                             'vlan_user_priority': '5'}

    acl_double_tag['dot1ad_dot1q']['stream'][4] = dict()
    acl_double_tag['dot1ad_dot1q']['stream'][4]['params'] = {'vlan_id': '10', 'vlan_cfi': '0',
                                                             'mac_src': '00:00:01:ab:cd:cc', 'vlan_id_outer': '200',
                                                             'vlan_outer_tpid': 34984, 'vlan_tpid': 33024,
                                                             'vlan_outer_cfi': 0,
                                                             'vlan_outer_user_priority': 5, 'mac_dst': '10:0b:a2:22:33:a2',
                                                             'vlan_user_priority': '4'}

    acl_double_tag['dot1ad_dot1q']['acl'] = dict()
    acl_double_tag['dot1ad_dot1q']['acl'][1] = dict()
    acl_double_tag['dot1ad_dot1q']['encap'] = """
        encapsulation dot1ad 200 dot1q 10
        """
    acl_double_tag['dot1ad_dot1q']['acl'][1]['ace_list'] = """
        10 deny host  0000.00ab.cdef host 1000.2222.3333  dei
        20 permit any host 1000.2222.3344 cos 2 dei
        30 deny host 0000.00ab.cd11 any cos 4
        """
    acl_double_tag['dot1ad_dot1q']['acl'][1]['stream'] = dict()

    acl_double_tag['dot1ad_dot1q']['acl'][1]['stream'][1] = dict()
    acl_double_tag['dot1ad_dot1q']['acl'][1]['stream'][1]['seq'] = 10

    acl_double_tag['dot1ad_dot1q']['acl'][1]['stream'][2] = dict()
    acl_double_tag['dot1ad_dot1q']['acl'][1]['stream'][2]['seq'] = 20

    acl_double_tag['dot1ad_dot1q']['acl'][1]['stream'][3] = dict()
    acl_double_tag['dot1ad_dot1q']['acl'][1]['stream'][3]['seq'] = 30

    acl_double_tag['dot1ad_dot1q']['acl'][1]['stream'][4] = dict()
    acl_double_tag['dot1ad_dot1q']['acl'][1]['stream'][4]['seq'] = 'implicit'

    return  acl_double_tag

def esacl_triggers_tc_dic() :
    esacl_triggers_tc = dict()
    esacl_triggers_tc['triggers'] = dict()
    esacl_triggers_tc['triggers']['tc_name'] = "ACL with double tag dot1q"
    esacl_triggers_tc['triggers']['direction'] = "ingress"
    esacl_triggers_tc['triggers']['stream'] = dict()
    esacl_triggers_tc['triggers']['stream'][1] = dict()
    esacl_triggers_tc['triggers']['stream'][1]['params'] = {'vlan_id': '10', 'mac_src': '10:11:33:44:55:66',
                                                            'vlan_id_outer': '4000',
                                                            'vlan_outer_tpid': 33024, 'vlan_tpid': 33024,
                                                            'vlan_outer_cfi': 1,
                                                            'vlan_outer_user_priority': 5, 'mac_dst': '01:80:c2:00:00:14',
                                                            'vlan_user_priority': '5'}

    esacl_triggers_tc['triggers']['stream'][2] = dict()
    esacl_triggers_tc['triggers']['stream'][2]['params'] = {'vlan_id': '10', 'mac_src': 'aa:aa:bb:bb:cc:cc',
                                                            'vlan_id_outer': '4000',
                                                            'vlan_outer_tpid': 33024, 'vlan_tpid': 33024,
                                                            'vlan_outer_cfi': 1, 'vlan_outer_user_priority': 7,
                                                            'mac_dst': '01:80:c2:00:00:15', 'vlan_user_priority': '5'}

    esacl_triggers_tc['triggers']['stream'][3] = dict()
    esacl_triggers_tc['triggers']['stream'][3]['params'] = {'vlan_id': '10', 'mac_src': '10:14:34:45:55:65',
                                                            'vlan_id_outer': '4000',
                                                            'vlan_outer_tpid': 33024, 'vlan_tpid': 33024,
                                                            'vlan_outer_cfi': 1,
                                                            'vlan_outer_user_priority': 3, 'mac_dst': 'ab:cd:ef:00:00:00',
                                                            'vlan_user_priority': '5'}

    esacl_triggers_tc['triggers']['stream'][4] = dict()
    esacl_triggers_tc['triggers']['stream'][4]['params'] = {'vlan_id': '10', 'vlan_cfi': '1',
                                                            'mac_src': '10:14:34:45:55:65', 'vlan_id_outer': '4000',
                                                            'vlan_outer_tpid': 33024, 'vlan_tpid': 33024,
                                                            'vlan_outer_cfi': 0,
                                                            'vlan_outer_user_priority': 5, 'mac_dst': 'ab:cd:ef:00:00:00',
                                                            'vlan_user_priority': '3'}

    esacl_triggers_tc['triggers']['acl'] = dict()
    esacl_triggers_tc['triggers']['acl'][1] = dict()
    esacl_triggers_tc['triggers']['encap'] = """
    encapsulation dot1q 4000 second-dot1q 10
    """
    esacl_triggers_tc['triggers']['acl'][1]['ace_list'] = """
    10 deny any host 0180.c200.0014
    20 deny any 0180.c200.0015 0000.0000.0000
    30 permit any any dei
    """
    esacl_triggers_tc['triggers']['acl'][1]['stream'] = dict()

    esacl_triggers_tc['triggers']['acl'][1]['stream'][1] = dict()
    esacl_triggers_tc['triggers']['acl'][1]['stream'][1]['seq'] = 10

    esacl_triggers_tc['triggers']['acl'][1]['stream'][2] = dict()
    esacl_triggers_tc['triggers']['acl'][1]['stream'][2]['seq'] = 20

    esacl_triggers_tc['triggers']['acl'][1]['stream'][3] = dict()
    esacl_triggers_tc['triggers']['acl'][1]['stream'][3]['seq'] = 30

    esacl_triggers_tc['triggers']['acl'][1]['stream'][4] = dict()
    esacl_triggers_tc['triggers']['acl'][1]['stream'][4]['seq'] = 'implicit'

    return  esacl_triggers_tc

def Single_ACE_Match_dic():
    Single_ACE_Match = dict()
    Single_ACE_Match['direction'] = dict()
    Single_ACE_Match['direction'] = "ingress"
    Single_ACE_Match['stream'] = dict()
    Single_ACE_Match['stream'][1] = dict()
    Single_ACE_Match['stream'][1]['params'] = {'vlan_id': '10', 'mac_src': '00:80:C2:00:00:14',
                                               'mac_dst': '00:10:00:AA:00:AA','vlan_user_priority': '0','vlan_cfi': '0'}

    Single_ACE_Match['stream'][2] = dict()
    Single_ACE_Match['stream'][2]['params'] = {'vlan_id': '20','mac_src': '00:80:C2:00:00:15',
                                               'mac_dst': '00:11:00:AA:00:BB','vlan_user_priority': '0','vlan_cfi': '0'}

    Single_ACE_Match['stream'][3] = dict()
    Single_ACE_Match['stream'][3]['params'] = {'vlan_id': '30', 'mac_src': '00:AA:00:BB:00:12',
                                               'mac_dst': '01:80:c2:00:00:14','vlan_user_priority': '0','vlan_cfi': '0'}

    Single_ACE_Match['stream'][4] = dict()
    Single_ACE_Match['stream'][4]['params'] = {'vlan_id': '40','mac_src': '00:AA:00:BB:00:13',
                                               'mac_dst': '01:80:c2:00:00:15','vlan_user_priority': '0','vlan_cfi': '0'}

    Single_ACE_Match['stream'][5] = dict()
    Single_ACE_Match['stream'][5]['params'] = {'vlan_id': '10', 'mac_src': '00:A0:CC:00:14:12',
                                               'mac_dst': '00:00:01:00:00:01', 'vlan_user_priority': '0',
                                               'vlan_cfi': '0'}

    Single_ACE_Match['stream'][6] = dict()
    Single_ACE_Match['stream'][6]['params'] = {'vlan_id': '20', 'mac_src': '00:A0:CC:11:14:AE',
                                               'mac_dst': '00:11:00:AA:00:BB', 'vlan_user_priority': '0',
                                               'vlan_cfi': '0'}

    Single_ACE_Match['stream'][7] = dict()
    Single_ACE_Match['stream'][7]['params'] = {'vlan_id': '30', 'mac_src': '00:10:94:00:00:02',
                                               'mac_dst': '01:00:20:00:04:AB', 'vlan_user_priority': '0',
                                               'vlan_cfi': '0'}

    Single_ACE_Match['stream'][8] = dict()
    Single_ACE_Match['stream'][8]['params'] = {'vlan_id': '40', 'mac_src': '00:10:94:00:00:11',
                                               'mac_dst': '01:01:21:00:04:A0', 'vlan_user_priority': '0',
                                               'vlan_cfi': '0'}
    Single_ACE_Match['stream'][9] = dict()
    Single_ACE_Match['stream'][9]['params'] = {'vlan_id': '130', 'mac_src': '00:10:31:2A:20:21',
                                                'mac_dst': '00:10:21:AA:01:12', 'vlan_user_priority': '7',
                                                'vlan_cfi': '0'}

    Single_ACE_Match['stream'][10] = dict()
    Single_ACE_Match['stream'][10]['params'] = {'vlan_id': '140', 'mac_src': '00:10:31:2A:2C:B1',
                                                'mac_dst': '00:10:21:AA:51:A2', 'vlan_user_priority': '1',
                                                'vlan_cfi': '0'}
    Single_ACE_Match['stream'][11] = dict()
    Single_ACE_Match['stream'][11]['params'] = {'vlan_id': '150', 'mac_src': '00:10:31:2A:90:A9',
                                                'mac_dst': '00:10:21:AA:81:02', 'vlan_user_priority': '2',
                                                'vlan_cfi': '1'}

    Single_ACE_Match['stream'][12] = dict()
    Single_ACE_Match['stream'][12]['params'] = {'vlan_id': '160', 'mac_src': '00:10:31:2A:21:31',
                                                'mac_dst': '00:10:41:AA:21:12', 'vlan_user_priority': '4',
                                                'vlan_cfi': '1'}


    Single_ACE_Match['stream'][13] = dict()
    Single_ACE_Match['stream'][13]['params'] = {'vlan_id': '101', 'mac_src': '00:10:00:AA:00:01',
                                               'mac_dst': '00:10:20:AA:10:AA','vlan_user_priority': '0','vlan_cfi': '0'}

    Single_ACE_Match['stream'][14] = dict()
    Single_ACE_Match['stream'][14]['params'] = {'vlan_id': '100','mac_src': '00:10:30:AA:20:01',
                                                'mac_dst': '00:10:20:AA:20:02','vlan_user_priority': '0','vlan_cfi': '0'}


    Single_ACE_Match['ace_list'] = """
    10 deny host 0080.c200.0014 any
    20 permit host 0080.c200.0015 any
    30 deny any host 0180.c200.0014
    40 permit any host 0180.c200.0015
    50 deny 00a0.cc00.1400 0000.0000.ffff any
    60 permit 00a0.cc11.1400 0000.0000.ffff any
    70 deny any 0100.2000.0400 0000.0000.ffff
    80 permit any 0101.2100.0400 0000.0000.ffff
    90 deny any any cos 7
    100 permit any any cos 1
    110 deny any any cos 2 dei
    120 permit any any cos 4 dei
    130 deny any any vlan 101
    140 permit any any vlan 100
    """
    #Put VLAN 10 for ACE 10, 20 for ACE 20 , 30 for ACE 30 and VLAN 40 for ACE 40, when VLAN SDK Bug is resolves.
    # VLAN from all the ACE's(10,20,30,40) to VLAN range vlan 1-4094 when VLAN range is supported
    Single_ACE_Match['stream'][1]['seq'] = 10
    Single_ACE_Match['stream'][2]['seq'] = 20
    Single_ACE_Match['stream'][3]['seq'] = 30
    Single_ACE_Match['stream'][4]['seq'] = 40
    Single_ACE_Match['stream'][5]['seq'] = 50
    Single_ACE_Match['stream'][6]['seq'] = 60
    Single_ACE_Match['stream'][7]['seq'] = 70
    Single_ACE_Match['stream'][8]['seq'] = 80
    Single_ACE_Match['stream'][9]['seq'] = 90
    Single_ACE_Match['stream'][10]['seq'] = 100
    Single_ACE_Match['stream'][11]['seq'] = 110
    Single_ACE_Match['stream'][12]['seq'] = 120
    Single_ACE_Match['stream'][13]['seq'] = 130
    Single_ACE_Match['stream'][14]['seq'] = 140

    return Single_ACE_Match

def acl_with_rewrite_dic() :
    acl_with_rewrite = dict()
    acl_with_rewrite['translate_1_to_2'] = dict()
    acl_with_rewrite['translate_1_to_2']['tc_name'] = "ACL with double tag dot1q"
    acl_with_rewrite['translate_1_to_2']['direction'] = "ingress"
    acl_with_rewrite['translate_1_to_2']['stream'] = dict()
    acl_with_rewrite['translate_1_to_2']['stream'][1] = dict()
    acl_with_rewrite['translate_1_to_2']['stream'][1]['params'] = {'vlan_id': '500', 'mac_src': '00:AB:30:04:A0:61',
                                                              'mac_dst': '10:00:22:22:33:33', 'vlan_user_priority': '3'}

    acl_with_rewrite['translate_1_to_2']['stream'][2] = dict()
    acl_with_rewrite['translate_1_to_2']['stream'][2]['params'] = {'vlan_id': '500', 'mac_src': '00:00:01:AB:CD:EF',
                                                              'mac_dst': '00:AB:30:04:A0:62', 'vlan_user_priority': '5','vlan_cfi': '1'}

    acl_with_rewrite['translate_1_to_2']['stream'][3] = dict()
    acl_with_rewrite['translate_1_to_2']['stream'][3]['params'] = {'vlan_id': '500', 'mac_src': '00:00:00:AB:CD:11',
                                                              'mac_dst': '10:00:22:22:33:10', 'vlan_user_priority': '7'}

    acl_with_rewrite['translate_1_to_2']['stream'][4] = dict()
    acl_with_rewrite['translate_1_to_2']['stream'][4]['params'] = {'vlan_id': '500', 'mac_src': '00:10:94:00:00:02',
                                                              'mac_dst': '00:00:01:00:00:01', 'vlan_user_priority': '0'}

    acl_with_rewrite['translate_1_to_2']['acl'] = dict()
    acl_with_rewrite['translate_1_to_2']['acl'][1] = dict()
    acl_with_rewrite['translate_1_to_2']['encap_main'] = """
    encapsulation dot1q 500
    rewrite ingress tag translate 1-to-2 dot1ad 10 dot1q 200 symmetric
    """
    acl_with_rewrite['translate_1_to_2']['encap'] = """
    encapsulation dot1ad 10 dot1q 200
    """
    acl_with_rewrite['translate_1_to_2']['acl'][1]['ace_list'] = """
    10 permit 00ab.3004.a060 0000.0000.00ff any cos 3
    20 deny any 00ab.3004.a060 0000.0000.00ff dei
    30 permit any any cos 7
    """
    acl_with_rewrite['translate_1_to_2']['acl'][1]['stream'] = dict()

    acl_with_rewrite['translate_1_to_2']['acl'][1]['stream'][1] = dict()
    acl_with_rewrite['translate_1_to_2']['acl'][1]['stream'][1]['seq'] = 10

    acl_with_rewrite['translate_1_to_2']['acl'][1]['stream'][2] = dict()
    acl_with_rewrite['translate_1_to_2']['acl'][1]['stream'][2]['seq'] = 20

    acl_with_rewrite['translate_1_to_2']['acl'][1]['stream'][3] = dict()
    acl_with_rewrite['translate_1_to_2']['acl'][1]['stream'][3]['seq'] = 30

    acl_with_rewrite['translate_1_to_2']['acl'][1]['stream'][4] = dict()
    acl_with_rewrite['translate_1_to_2']['acl'][1]['stream'][4]['seq'] = 'implicit'

    acl_with_rewrite['pop_1'] = dict()
    acl_with_rewrite['pop_1']['tc_name'] = "ACL with double tag dot1ad and secondary dot1q"
    acl_with_rewrite['pop_1']['direction'] = "ingress"
    acl_with_rewrite['pop_1']['stream'] = dict()
    acl_with_rewrite['pop_1']['stream'][1] = dict()
    acl_with_rewrite['pop_1']['stream'][1]['params'] = {'vlan_id': '90', 'mac_src': '00:11:00:ab:cd:1f',
                                                             'mac_dst': '10:10:22:12:31:33', 'vlan_id_outer': '300',
                                                             'vlan_outer_tpid': 33024, 'vlan_tpid': 33024,
                                                             'vlan_outer_cfi': 1,
                                                             'vlan_outer_user_priority': '7', 'vlan_user_priority': '5'}


    acl_with_rewrite['pop_1']['stream'][2] = dict()
    acl_with_rewrite['pop_1']['stream'][2]['params'] = {'vlan_id': '90', 'mac_dst': '10:10:22:82:39:04',
                                                             'vlan_id_outer': '300',
                                                             'vlan_outer_tpid': 33024, 'vlan_tpid': 33024,
                                                             'vlan_outer_cfi': 1, 'vlan_outer_user_priority': 2,
                                                             'mac_src': '00:00:01:1a:cd:ef', 'vlan_user_priority': '5'}

    acl_with_rewrite['pop_1']['stream'][3] = dict()
    acl_with_rewrite['pop_1']['stream'][3]['params'] = {'vlan_id': '90', 'mac_src': '00:00:10:ab:c0:11',
                                                             'vlan_id_outer': '300',
                                                             'vlan_outer_tpid': 33024, 'vlan_tpid': 33024,
                                                             'vlan_outer_cfi': 0,
                                                             'vlan_outer_user_priority': 4, 'mac_dst': '10:00:22:22:33:10',
                                                             'vlan_user_priority': '5'}

    acl_with_rewrite['pop_1']['stream'][4] = dict()
    acl_with_rewrite['pop_1']['stream'][4]['params'] = {'vlan_id': '90', 'vlan_cfi': '0',
                                                             'mac_src': '00:00:01:ab:cd:cc', 'vlan_id_outer': '300',
                                                             'vlan_outer_tpid': 33024, 'vlan_tpid': 33024,
                                                             'vlan_outer_cfi': 0,
                                                             'vlan_outer_user_priority': 5, 'mac_dst': '10:0b:a2:22:33:a2',
                                                             'vlan_user_priority': '4'}

    acl_with_rewrite['pop_1']['acl'] = dict()
    acl_with_rewrite['pop_1']['acl'][1] = dict()
    acl_with_rewrite['pop_1']['encap_main'] = """
        encapsulation dot1q 300 second-dot1q 90
        rewrite ingress tag pop 1 symmetric
        """
    acl_with_rewrite['pop_1']['encap'] = """
    encapsulation dot1q 90
    """
    acl_with_rewrite['pop_1']['acl'][1]['ace_list'] = """
    10 deny host  0011.00ab.cd1f host 1010.2212.3133  cos 7 dei
    20 permit any host 1010.2282.3904 cos 2 dei
    30 deny host 0000.10ab.c011 any cos 4
    """
    acl_with_rewrite['pop_1']['acl'][1]['stream'] = dict()

    acl_with_rewrite['pop_1']['acl'][1]['stream'][1] = dict()
    acl_with_rewrite['pop_1']['acl'][1]['stream'][1]['seq'] = 10

    acl_with_rewrite['pop_1']['acl'][1]['stream'][2] = dict()
    acl_with_rewrite['pop_1']['acl'][1]['stream'][2]['seq'] = 20

    acl_with_rewrite['pop_1']['acl'][1]['stream'][3] = dict()
    acl_with_rewrite['pop_1']['acl'][1]['stream'][3]['seq'] = 30

    acl_with_rewrite['pop_1']['acl'][1]['stream'][4] = dict()
    acl_with_rewrite['pop_1']['acl'][1]['stream'][4]['seq'] = 'implicit'

    return  acl_with_rewrite