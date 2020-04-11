# To run the job:
# easypy $VIRTUAL_ENV/examples/connection/job/connection_example_job.py \
#        -testbed_file \
#        $VIRTUAL_ENV/examples/connection/etc/connection_example_conf.yaml
#
# Description: This example uses a sample testbed, connects to a device
#              which name is passed from the job file,
#              and executes some commands. The goal is to show
#              how devices can be chosen dynamically and passed to the script.

#import os
#from ats.easypy import run
#from ats.datastructures.logic import And, Or, Not

import os
import logging
from ats.easypy import run
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

def main():
    # Find the location of the script in relation to the job file
    test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    #testscript = os.path.join(test_path, 'connection_example_script.py')
    testscript = '/ws/ikyalnoo-bgl/pyatsgit/esacl_1.0/ESACL_SCRIPT.py'

    # Do some logic here to determine which devices to use
    # and pass these device names as script arguments
    # ...
    #chosen_uut_device = 'ott-tb1-n7k3'
    chosen_uut_device = 'fretta'
    stdby_device = 'notreallyadevice'
    enable_port_xconnect = 0 #### to enable port_xconnect streems ####



    run(testscript=testscript,
        uut_name=chosen_uut_device,
        stdby_name=stdby_device ,
        R1=chosen_uut_device,
        intf_mode = 'suninterface',
        init_clean = 0,
        console_type='console',
        config_lang_phy_mode=0,
        mtu_size_list=[1600,9210,9216],
        mac_dst_type='UNICAST',
        frame_size_with_CRC=[504,9214,9220],
        R1_TGN_int1 = 'tengige0/0/0/0',
        R1_TGN_int2 ='tengige0/0/0/2',
        TGN_R1_int1 = '4/9',
        TGN_R1_int2 ='4/11',
        tgn_name = 'TGN-SPIRENT',
        pkts_per_burst = 500,
        efp_exact = 0,
        eth_autonego = 0,
        vlan_header_cos= 6,
        speed="ether10000",
        failover_tests = ['mtu_test_with_max_pkts_size', 'mtu_test_with_max_plus_2_pkts_size', 'mtu_test_with_max_plus_4_pkts_size', 'mtu_test_with_max_plus_6_pkts_size'] ,
        port_xconnect = enable_port_xconnect,
        #groups = Or('group1'),
        validate_pkt_hex = 1,
        cfg_permutations = 1, #skip =  'cfg_permutations',
        #poss_failover_list = ['l2.es.xc.dot1ad_pri_tag_push1q','l2.es.xc.dot1q_vid_translate1_2ad_q','l2.es.xc.in_dot1ad_out_dot1ad_pop1','l2.es.xc.default_efp_untag'],
        #poss_failover_list = ['l2.es.xc.dot1ad_pri_tag_push1q'],
        poss_failover_list = ['l2.es.xc.dot1q_push1q'],
        #poss_failover_list = ['l2.es.xc.in_dot1ad_out_dot1ad_pop1'],
        #config_data_yaml_file='/ws/ikyalnoo-bgl/pyats/examples/scripts/VPWS_NEW_DYANMIC/config_data.yaml',
        bundle_interface = 0,
        run_ids=['common_setup', 'L2aclPositive_BasicACL','L2aclPositive_acl_edits','L2aclPositive_atomic_replace','L2aclPositive_Single_ACE_Match','L2aclPositive_acl_double_tag','L2aclPositive_with_rewrite_tag','common_cleanup']
        #ids=Or('common_setup','L2aclPositive_BasicACL','L2aclPositive_acl_edits','L2aclPositive_atomic_replace','L2aclPositive_Single_ACE_Match','L2acl_triggers_tc','L2aclPositive_acl_double_tag','L2aclPositive_with_rewrite_tag','common_cleanup')
         # )

       )
