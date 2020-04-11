#!/bin/env python

###################################################################
# ESACL_SCRIPT.py : A test script example which includes:
#     common_seup section - device connection, configuration
#     Tescase section with testcase setup and teardown (cleanup)
#     common_cleanup section - device cleanup
#The purpose of this test script is to test permutations for L2 ACL(ESACL) Physical SubInterface and Main Interface
# devices/UUT in the common setup section. How to run few simple testcases
# And finally, recover the test units in
# the common cleanup section. Script also provides an example on how to invoke
# TCL interpreter to call existing TCL functionalities.
###################################################################

import sys
import pdb
from ats import tcl
from ats import aetest
from ats.atslog.utils import banner
from ats import topology
from ats.tcl import tclstr
#from l2vpn_lib import *
import re
import logging
import sys
import pprint
import time
import random
import math
import copy
from ESACL_lib import *
import tgen_spi as spirent
import collections
from ats.connections.csccon.exceptions import ConnectionTimedOutError


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log_user = 1
eth_autonego='1'
#from tgen_spi import *

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

tcl.eval('source /users/kmirji/scapa/arwen/cross_connect_automation/health_check.lib')
tcl.eval('source /users/kmirji/scapa/arwen/cross_connect_automation/scapa_arwen_bth_lib.tcl')
cfm=0
qos=0
def cfm_precheck():
    global cfm
    assert cfm is 1

def qos_precheck():
    global qos
    assert qos is 1

global port_data
port_data = dict()


class ForkedPdb(pdb.Pdb):
    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        try:
            sys.stdin = open('/dev/stdin')
            pdb.Pdb.interaction(self, *args, **kwargs)
        finally:
            sys.stdin = _stdin

def check_xc_state(rtr, group_name):
    success = True
    count_xcon = 0
    msg = ''

    try:
        res = tcl.eval('router_show -device %s -cmd "show l2vpn xconnect group %s" -os_type xr' % (
        rtr.handle, group_name))
        python_result = tcl.cast_keyed_list(res)

        if python_result['xc_group'] == '':
            msg += "XC Output from 'show l2vpn xconnect' BAD!. "
            log.error("XC Output from 'show l2vpn xconnect' BAD!")
            success = False
        else:
            xc_con = python_result['xc_group'].keys()
            for con in xc_con:
                xc_state = python_result['xc_group'][con]['xc_state']
                if not xc_state:
                    msg += "XC Output from 'show l2vpn xconnect' BAD!. "
                    log.error("XC Output from 'show l2vpn xconnect' BAD!")
                    success = False
                elif xc_state == "up":
                    count_xcon += 1
                    log.info("XC state %s is up as expected." % con)
                else:
                    msg += "XC state %s is not up. " % con
                    log.error("XC state %s is not up" % con)
                    success = False
    except Exception as e:
        log.error('XC state check failed as %s' % e)
        msg += "XC state check failed as %s. " % e
        success = False

    return (success, msg)

def verify_stats(uut,tx_pkts,rx_pkts,seq,acl_name,direction,loc,traffic_tolerance,stream) :
    router = uut
    tx_pkt = tx_pkts
    rx_pkt = rx_pkts
    seq_num = seq
    success = True
    #ForkedPdb().set_trace()
    op = tcl.eval(
        'router_show -device %s -cmd "show access-lists ethernet-services %s hardware %s location %s" -os_type xr' % (
            router.handle, acl_name, direction, loc + "/CPU0"))
    result = tcl.cast_keyed_list(op)
    #comd = "show access-lists ethernet-services %s hardware %s location %s" % (acl_name, direction, loc + "/CPU0")
    if (seq != 'implicit'):
        comd = "show access-lists ethernet-services %s hardware %s sequence %s location %s" % (acl_name, direction, seq, loc + "/CPU0")
        output = router.execute(comd)
        if re.search("(\d+)\s+matches", output):
            hw_stats = re.search("(\d+)\s+matches", output).group(1)
        else:
            hw_stats = 0
    if (seq == 'implicit'):
        cmd = "show access-lists ethernet-services %s hardware %s implicit detail location %s" % (
        acl_name, direction, loc + "/cpu0")
        output = router.execute(cmd)
        if re.search("Hit\s+Packet\s+Count:\s+(\d+)", output):
            hw_stats = re.search("Hit\s+Packet\s+Count:\s+(\d+)", output).group(1)
        else:
            hw_stats = 0
        ace = re.search("Sequence\s+Number:\s+(\S+\s+\S+)", output).group(1)
    else:
        ace = result['acl'][acl_name]['seq'][seq]['ace']
    res = (re.search(r'(\S+)', ace)).group(1)
    if res is False:
        log.info("unable to get the result for seq %s" % seq)
        success = False
        return success
    log.info("matching seq %s action %s acc-counters=%s" % (seq, res, hw_stats))
    if (res == 'permit'):
        if rx_pkts == tx_pkts:
            sucess = True
            return sucess
        else:
            diff = (tx_pkts - rx_pkts)
            if diff < 0:
                diff = diff * -1
                percentage = diff / tx_pkts
                if percentage < traffic_tolerance:
                    log.info("seq %s expected action is permit , rx  and  tx are tx=%d rx=%d" % (
                        seq, tx_pkt, rx_pkt))
                    sucess = True
                    return sucess
                else:
                    log.error("seq %s expected action is permit but rx is not equal to tx actual tx=%d rx=%d" % (
                        seq, tx_pkt, rx_pkt))
                    sucess = False
                    return sucess
            else:
                percentage = diff / tx_pkts
                if percentage < traffic_tolerance:
                    sucess = True
                    return sucess
                else:
                    log.error("seq %s expected action is permit but rx is not equal to tx actual tx=%d rx=%d" % (
                        seq, tx_pkt, rx_pkt))
                    sucess = False
                    return sucess
    if (result == 'deny' and (rx_pkt != 0)):
        log.error("seq %s expected action is deny but rx is not equal 0 actual is rx=%d" % (seq, rx_pkt))
        success = False
        return success
    if (res != 'permit'):
        hw_pkt = int(hw_stats)
        if hw_pkt == tx_pkt:
            sucess = True
            return sucess
        else:
            diff = (tx_pkt - hw_pkt)
            if diff < 0:
                diff = diff * -1
                percentage = diff / tx_pkts
                if percentage < traffic_tolerance:
                    sucess = True
                    return sucess
                else:
                    log.error(
                        "stream %s HW countersw mismatch for seq %s , expected hits = %d , actucla hits = %s" % (
                            stream, seq, tx_pkts, hw_stats))
                    sucess = False
                    return sucess
            else:
                percentage = diff / tx_pkts
                if percentage < traffic_tolerance:
                    sucess = True
                    return sucess
                else:
                    log.error(
                        "stream %s HW countersw mismatch for seq %s , expected hits = %d , actucla hits = %s" % (
                            stream, seq, tx_pkts, hw_stats))
                    sucess = False
                    return sucess
    return success

def verify_stats_without_acl(rx_pkts,tx_pkts,traffic_tolerance):
    sucess = True
    if tx_pkts == 0:
        log.info("Tx Packets are 0")
        sucess = False
        return sucess
    rx_pkts = int(rx_pkts)
    tx_pkts = int(tx_pkts)
    if rx_pkts == tx_pkts:
        sucess = True
        log.info(" Traffic test passed, tx and rx are as expected tx=%d and rx=%d" % (tx_pkts, rx_pkts))
        return sucess
    else:
        diff = (tx_pkts - rx_pkts)
        if diff < 0:
            diff = diff * -1
            percentage = diff / tx_pkts
            if percentage < traffic_tolerance:
                sucess = True
                log.info(" Traffic test passed, tx and rx are as expected tx=%d and rx=%d" % (tx_pkts, rx_pkts))
                return sucess
            else:
                log.error(" Traffic test failed, tx and rx are not as expected tx=%d and rx=%d" %(tx_pkts,rx_pkts))
                sucess = False
                return sucess
        else :
            percentage = diff / tx_pkts
            if percentage < traffic_tolerance:
                sucess = True
                return sucess
            else:
                log.error(" Traffic test failed, tx and rx are not as expected tx=%d and rx=%d" % (tx_pkts, rx_pkts))
                sucess = False
                return sucess
    return sucess

def verify_show_logging_context(rtr):
    """ Verify show logging and show context. Raise Exception in faliure"""

    success = True

    try:
        rtr.execute('show logging')
        log.info("Show logging execution passed")
    except ConnectionTimedOutError as err:
        log.error(err)
        wait_time = 300
        log.info("waiting for {}s. as connection timedout"
                  .format(wait_time))
        time.sleep(wait_time)
    except Exception as err:
        log.info(err)
        log.error('show logging execution failed')
        log.error("Exception type: {}".format(str(err)))
        wait_time = 300
        log.info("waiting for {}s, suspecting connection timedout"
                  .format(wait_time))
        time.sleep(wait_time)
        success = False

    command = r'''show logging | include \"CPUHOG|MALLOCFAIL|Traceback'''
    command += r'''|_ERROR|abnormally|FATAL\"'''
    logging_out = rtr.execute(command)
    ptrn = "(CPUHOG.*)|(MALLOCFAIL.*)|(Traceback.*)|(_ERROR.*)|(abnormally.*)|(FATAL.*)|(restart.*)"
    flag = 0
    for line in logging_out.split('\r\n'):
        matchObj = re.search("show logging.*", line, re.I)
        if matchObj:
            continue
        matchObj = re.search(".*UTC", line, re.I)
        if matchObj:
            continue
        matchObj = re.search("0\/RP[0|1]\/CPU0.*#", line, re.I)
        if matchObj:
            continue
        matchObj = re.search(ptrn, line, re.I)
        if matchObj:
            flag += 1
    if flag:
        msg = "Observed error messages in show logging. "
        log.error(msg)
        success = False
    else:
        msg = "No error messages observed in show logging"
        log.info(msg)

    try:
        pyRes = rtr.verify('show context location all', parse_only = 'yes', parser_type = 'textfsm')

        pids = list()
        if 'pid' in pyRes:
            pids = pyRes['pid'].keys()
            crashnames = list()
            for pid in pids:
                crashnames.append(pyRes['pid'][pid]['name'])

            msg = ('Cores/crashes %s Found. ' % crashnames)
            log.error(msg)
            success = False
        else:
            log.info("No Crashes Found")
    except:
        msg = ('Failed to parse show context in the router %s ' % rtr)
        log.error(msg)
        success = False

    try:
        rtr.transmit('admin\r')
        rtr.receive('sysadmin-vm.*')
        rtr.execute('terminal length 0')

        pyRes = rtr.verify('show context location all', parse_only = 'yes', parser_type = 'textfsm')

        pids = list()
        if 'pid' in pyRes:
            pids = pyRes['pid'].keys()
            crashnames = list()
            for pid in pids:
                crashnames.append(pyRes['pid'][pid]['name'])
            msg = ('Cores/crashes %s Found. ' % crashnames)
            log.error(msg)
            success = False
        else:
            log.info("No Crashes Found")

        rtr.execute("clear context location all")

        rtr.transmit('exit\r')
        if not rtr.receive(r'RP/0/RP[0-1].*\#', timeout = 5):
            log.error('Router is not in xr prompt')
            success = False
    except:
        msg = ('Failed to parse show context in the router %s ' % rtr)
        log.error(msg)
        success = False

    try:
        rtr.execute("clear logging")
        rtr.execute("clear context location all")
        log.info("Clear logging and context passed")
    except:
        msg = ("Clear logging and context failed. ")
        log.error(msg)
        success = False

    return success

def admin_lc_reload(device, location, num_retry=10, interval=30):

    '''
        Description: hw-module Line Card Reload.

        Arguments:
            device: Router Device Object

            location: location of line card module

            Optional args

            num_retry: number of retries for verification if it fails.

            interval: sleep interval for each retry

        Returns:
            Raise Exception on Error
    '''

    success = True
    log.info("Entering Event line card reload")

    #Pre-Verification
    verify_data = {'node':[location], 'hwstate':['operational'], 'swstate': ['operational']}

    device.verify('show platform', os_type='calvados', **verify_data)

    pre_int_out = device.verify('show interfaces summary', parse_only='yes')

    total_ints = pre_int_out['all_types']['total']
    int_summ_verify = {"interface":['all_types'], "total":[total_ints]}

    #Event
    try:
        device.rp_calv_exec("hw-module location %s reload" % location, answer='yes')
    except Exception as err:
        errMsg = 'Failed to reload %s: %s' % (location, str(err))
        log.error(errMsg)
        return False

    log.info("Applying Sleep for 150 sec")
    time.sleep(150)

    #Post-Verification
    try:
        device.verify('show platform', os_type='calvados', \
                num_retrials=num_retry, interval=interval, **verify_data)
        log.info("Post-Verification PASSED, LC at location %s is UP" % location)
    except Exception as err:
        errMsg = 'Post_Verification Failed, LC at location %s is not \
                Operational: %s' % (location,str(err))
        log.error(errMsg)
        success = False

    try:
        device.verify('show interfaces summary', \
                      num_retrials=num_retry, interval=interval, \
                      **int_summ_verify)
        log.info("Post-Verification PASSED, Total %s Interfaces Created" % total_ints)
    except Exception as err:
        errMsg = 'Post-Verification Failed, Interfaces not Found: %s' % (str(err))
        log.error(errMsg)
        success = False
    return success






###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################

# Configure and setup all devices and test equipment in this section.
# This should represent the BASE CONFIGURATION that is applicable
# for the bunch of test cases that would follow.

class common_setup(aetest.CommonSetup):

    @aetest.subsection
    def connect(self):
        """ common setup subsection: connecting devices """
        tcl.eval("package require dataUtils")
        tcl.eval('package require router_show')
        tcl.eval('package require rtrUtils')
        tcl.eval('package require xr')


        global stc_intf_list
        global speed
        global pkt_size
        global data_percent
        global rtr_intf_list

        global cfm
        global qos
        global efp_types
        global all_tests_list
        global subtests_to_skip
        global pkts_per_burst
        global stc_port_list
        stc_port_list = []
        pkt_size = '1496'
        self.script_args['pkt_size'] = pkt_size
        data_percent = '10'
        self.script_args['data_percent'] = data_percent
        traffic_tolerance = 0.2

        # Grab the device object of the uut device with that name
        LC = []
        uut_name = self.script_args['uut_name']
        uut = self.script_args['testbed'].devices[uut_name]
        self.script_args['uut_name'] = uut_name
        self.script_args['uut'] = uut
        tgen =  self.script_args['testbed'].devices['TGN-SPIRENT']
        self.script_args['tgn_name'] = 'TGN-SPIRENT'
        self.script_args['unconfig'] = ""
        tgen_pkt_rate = 10000  # need some fix
        pkts_per_burst = 1000
        count = 0
        log.info(' tgen information  %s \n' % tgen)
        # Grab all device interfaces and tgen interfaces
        R1_TGN_int1 = self.script_args['R1_TGN_int1']
        TGN_R1_int1 = self.script_args['TGN_R1_int1']
        R1_TGN_int2 = self.script_args['R1_TGN_int2']
        TGN_R1_int2 = self.script_args['TGN_R1_int2']
        rtr_intf_list=[R1_TGN_int1,R1_TGN_int2]
        stc_port_list=[TGN_R1_int1,TGN_R1_int2]
        #stc_port_list.sort()
        self.script_args['rtr_intf_list'] = rtr_intf_list
        log.info('rtr_intf_list %s' % rtr_intf_list)
        speed='ether10000'
        global port_data
        port_data = dict()
        port_data[uut_name] = dict()
        port_data['TGN'] = dict()
        port_data['TGN']['neighbors'] = dict()
        port_data[uut_name]['neighbors'] = dict()
        port_data['TGN']['neighbors'][uut_name] = dict()
        port_data['TGN']['neighbors'][uut_name][1] = dict()
        port_data['TGN']['neighbors'][uut_name][1]['interface'] = TGN_R1_int1
        port_data[uut_name]['neighbors']['TGN-SPIRENT'] = dict()
        port_data[uut_name]['neighbors']['TGN-SPIRENT'][1] = dict()
        port_data[uut_name]['neighbors']['TGN-SPIRENT'][1]['interface'] = dict()
        port_data[uut_name]['neighbors']['TGN-SPIRENT'][1]['interface']['name'] = R1_TGN_int1
        port_data[uut_name]['neighbors']['TGN-SPIRENT'][1]['interface']['subinterface'] = dict()
        port_data['TGN']['neighbors'][uut_name][2] = dict()
        port_data['TGN']['neighbors'][uut_name][2]['interface'] = TGN_R1_int2
        port_data[uut_name]['neighbors']['TGN-SPIRENT'][2] = dict()
        port_data[uut_name]['neighbors']['TGN-SPIRENT'][2]['interface'] = dict()
        port_data[uut_name]['neighbors']['TGN-SPIRENT'][2]['interface']['name'] = R1_TGN_int2
        port_data[uut_name]['neighbors']['TGN-SPIRENT'][2]['interface']['subinterface'] = dict()
        # Connect to the device
        while True:
            try:
                uut.connect()
                log.info("connection retry :%s" % count)
                break
            except Exception as e:
                count += 1
                time.sleep(2)
                if count > 5:
                    log.info("failed to connect")
                    self.failed(goto=['common_cleanup'])
                    break
                    # print(dir(uut))
        efp_types=self.script_args.get('efp_types',[])
        req_stc_port_list = [TGN_R1_int1,TGN_R1_int2]
        stc_port_list = req_stc_port_list
        self.script_args['stc_port_list'] = stc_port_list
        self.script_args['port_data'] = port_data
        ac_interface = []
        for i in range(1,3):
            ac_interface.append(port_data[uut_name]['neighbors']['TGN-SPIRENT'][i]['interface']['name'])
        self.script_args['ac_interface'] = ac_interface
        log.info("stc_port_list %s" % stc_port_list)
        log.info('port_data: %s' % pprint.pformat(port_data))
        init_clean = self.script_args['init_clean']
        startup_file = "harddisk:startup-config"
        with self.steps.start('port based') as step:
            if init_clean:  # need some test on startup file
                try:
                    result = tcl.eval(
                        '::xr::unconfig::router -device %s -load_file %s" -os_type xr' % (uut.handle, startup_file))
                    status = tcl.cast_keyed_list(result)
                    log.info(' interface result %s' % str(status))
                except Exception as e:
                    log.error(' Failed to load startup config %s ' % e)
                    self.failed()
        with self.steps.start('Connect to sth and get port handles') as step:
            try:
                port_handles=[]
                #tgen="10.105.241.41"
                tgen_ip = self.script_args['testbed'].devices['TGN-SPIRENT'].connections['spirent']['tcl_server']
                self.script_args['tgen_ip_var'] = tgen_ip
                log.info("tgen ip : %s" % tgen_ip)

                intfStatus=spirent.sth.connect(
                                        device=tgen_ip,
                                        port_list=stc_port_list,
                                        break_locks=1,
                                        offline=0)
                log.info("intf Status %s" % pprint.pformat(intfStatus))
                status=intfStatus['status']


                if status == '0':
                    log.error('Connect to sth and get port handles failed')
                    self.failed()

                if status == '1':
                    for port in stc_port_list:
                        port_handles.append(intfStatus['port_handle'][tgen_ip][port])

                    self.script_args['tgen_hdls'] = port_handles
                    neighbors=port_data['TGN']['neighbors'][uut_name]
                    for idx in neighbors.keys():
                        port=neighbors[idx]['interface']
                        porthdl=intfStatus['port_handle'][tgen_ip][port]
                        port_data['TGN']['neighbors'][uut_name][idx]['handle']=porthdl
            except Exception as e:
                log.error(' Connect to sth and get port handles failed as %s ' % e)
                self.failed()
            try:
               result = tcl.eval('::dataUtils::calc_pkt_rate -intf_type %s -pkt_size %d -encap ether2 -percent_load %d' % \
                                             (speed,int(pkt_size),int(data_percent)))
               log.info("result info %s" % result)
               packet_rate_info = tcl.cast_keyed_list(result)
               log.info("packet_rate_info %s" % packet_rate_info)
               tgen_pkt_rate = packet_rate_info['pps']
               log.info("tgen_pkt_rate : %s" % tgen_pkt_rate )
               tgen_pkt_rate = 10000  #doubt need some fix

            except Exception as e:
                log.error(' Packet rate determination failed as %s ' % e)

            speed='ether10000'
            if speed == 'ether100000':
                speed='ether100000'

            for hdl in port_handles:
                speed = "ether1000"
                intf_ret1 = spirent.sth.interface_config(
                         mode = 'config',
                         port_handle = hdl,
                         create_host  = 'false',
                         speed = speed,
                         duplex = 'full',
                         phy_mode='fiber',
                         autonegotiation = eth_autonego,
                         enable_ping_response = 1,
                         scheduling_mode  = 'RATE_BASED'
                        )
                status = intf_ret1['status']
                log.info("intf_ret %s" % pprint.pformat(intf_ret1))
                if status == '0':
                    log.info('run sth::intf_ret1 failed')
                    print(intf_ret1)
                else:
                    log.info( "***** run sth::interface_config successfully")
        with self.steps.start('configuring L2vpn xconnect') as step:
            intf_mode = self.script_args['intf_mode']
            interfaces = []
            self.script_args['speed'] = speed
            #pdb.set_trace()
            neighbor = port_data[uut_name]['neighbors']['TGN-SPIRENT']
            for indx in neighbor.keys() :
                intf = port_data[uut_name]['neighbors']['TGN-SPIRENT'][indx]['interface']['name']
                interfaces.append(intf)
                conf = '''
                no interface %s.*
                no interface %s
                interface %s
                no shutdow
                ''' %(intf,intf,intf)
                uut.config(conf)
                if intf_mode == 'interface':
                    conf_str = '''
                    interface %s
                     l2transport
                    '''%(intf)
                    uut.config(conf_str)
                elif intf_mode == 'subinterface':
                    conf_str = '''
                    interface %s l2transport
                    encapsulation default
                    no shutdown
                    '''%(intf+".100")
                    uut.config(conf_str)
                else:
                    log.info("invalid argument for intf mode , valid are interface or subinterface")
            LC.append(re.search(r'(\d/\d)[0-9/]+', port_data[uut_name]['neighbors']['TGN-SPIRENT'][1]['interface']['name']).group(1))
            self.script_args['LOC'] = LC
            if intf_mode == 'interface':
                conf_str = '''
                    no l2vpn
                    l2vpn
                      xconnect group XCON
                      p2p p1
                    interface %s
                    interface %s
                    '''%(interfaces[0],interfaces[1])
                uut.config(conf_str)
            elif intf_mode == 'subinterface':
                conf_str = '''
                    no l2vpn
                    l2vpn
                      xconnect group XCON
                      p2p p1
                    interface %s
                    interface %s
                    ''' % (interfaces[0]+".100", interfaces[1]+".100")
                uut.config(conf_str)
                self.script_args['subinterface'] = [interfaces[0]+".100", interfaces[1]+".100"]
            else:
                log.info("invalid argument for intf mode , valid are interface or subinterface")
            log.info("Clearng the context before starting the Testing")
            try:
                uut.execute("show context")
                uut.execute("clear context")
                uut.execute("show context")
            except Exception as e:
                log.error("not able to clear the context")
            #pdb.set_trace()
            for i in (0,1) :
                cmd = "show interfaces %s" %(interfaces[i])
                sucess = False
                for j in range(1,5):
                    time.sleep(2)
                    result = uut.execute(cmd)
                    if (re.search(r'line\s+protocol\s+is\s+up' ,result)) :
                        sucess = True
                        break
                if not sucess:
                    log.info("interfaces %s , in not up" % (interfaces[i]))
                    self.failed(goto=['cleanup'])
            (xcon_res,xcon_msg) = check_xc_state(uut,"XCON")
            if xcon_res :
                log.info("XCONECT is UP")
                log.info(xcon_msg)
            else :
                log.error("XCONEECT is not up %s" %xcon_msg)
                self.failed(goto=['cleanup'])
            streams = {'1':{'params':{'mac_src':'10:22:33:44:55:66','vlan_id':'100'}}}
            stream_ids = dict()
            handle = []
            for direction in ['ingress' , 'egress']:
                failure_hex = 0
                if (direction == 'ingress') :
                    handle_tx = self.script_args['tgen_hdls'][0]
                    handle_rx = self.script_args['tgen_hdls'][1]
                else :
                    handle_tx = self.script_args['tgen_hdls'][1]
                    handle_rx = self.script_args['tgen_hdls'][0]
                stream_ids[handle_tx] = []
                for i in list(streams.keys()) :
                    params = streams[i]['params']
                    if 'mac_src' not in params:
                        streams[i]['params']['mac_src']='aa:bb:cc:dd:ee:ff'
                    if 'mac_dst' not in params:
                        streams[i]['params']['mac_dst'] = 'ff:ee:dd:cc:bb:aa'
                    if 'l3_protocol' not in params :
                        streams[i]['params']['l3_protocol'] = 'ipv4'
                    if 'vlan_id' not in params:
                        streams[i]['params']['vlan_id'] = '100'
                    try :
                        try:
                            trafficList = spirent.sth.traffic_config(inter_stream_gap_unit='bytes',
                                                                     mac_src_step=1,
                                                                     ip_src_mode='fixed',
                                                                     l2_encap='ethernet_ii_vlan',
                                                                     mac_src_mode='fixed',
                                                                     length_mode='fixed',
                                                                     mac_dst_step=1,
                                                                     rate_pps=tgen_pkt_rate,
                                                                     ip_dst_mode='fixed',
                                                                     mac_dst_mode='fixed',
                                                                     l3_protocol='ipv4',
                                                                     mac_dst=streams[i]['params']['mac_dst'],
                                                                     enable_stream_only_gen=0,
                                                                     ip_ttl=64,
                                                                     inter_stream_gap='116.0',
                                                                     mode='create',
                                                                     frame_size=pkt_size,
                                                                     transmit_mode='continuous',
                                                                     pkts_per_burst=pkts_per_burst,
                                                                     mac_src=streams[i]['params']['mac_src'],
                                                                     vlan_id=streams[i]['params']['vlan_id'],
                                                                     #vlan_tpid:'33024',
                                                                     port_handle=handle_tx,
                                                                     #port_handle=handle,
                                                                     enable_stream=0,
                                                                     )
                            stream_ids[handle_tx].append(trafficList['stream_id'])
                            self.script_args['stream_ids'] = stream_ids
                        except Exception as e:
                                log.error(' sth.traffic_config for %s Failed trafficconfig_result:%s error: %s' %
                                          (tgen, str(trafficList), e))
                    except Exception as e:
                        log.error(' sth.traffic_config for %s Failed trafficconfig_result:%s error: %s' %
                                            (tgen_ip,str(trafficList),e))
                #ForkedPdb().set_trace()
                log.info("Clear stats before starting the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                    log.info('Traffic clear status : %s' % result['status'])
                except Exception as e:
                    log.error('Failed to clear port counters: %s ' % e)
                    self.failed()

                #with self.steps.start("Start the capture to get the capure packets") as step:
                log.info("Starting the traffic for 7secs")
                try:
                    result=spirent.sth.traffic_control(port_handle=handle_tx,action="run")
                except Exception as e:
                    log.error('Failed to start traffic: ' % e)
                    self.failed(goto=['cleanup'])
                    time.sleep(7)
                log.info("stoping the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                    log.info("Poling: STC to see if traffic has stopped")
                    # poling need to check
                except Exception as e:
                    log.error('Failed to stop the  traffic: ' % e)
                    self.failed(goto=['cleanup'])

                log.info("checking the traffic stats and verifying the TX and RX packets")
                try :
                    stats_list = spirent.sth.traffic_stats(port_handle = handle_tx, mode = 'streams', rx_port_handle = 'all',)
                except Exception as e:
                    log.error('Failed collect the stats and hence verification got failed for the traffic:: %s ' % e)
                    self.failed(goto=['cleanup'])
                    failure_hex += 1
                for stream in stream_ids[handle_tx] :
                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                        rx_pkts = 0
                    else:
                        rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                        tx_pkts = 0
                    else:
                        tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                    rx_pkts = int(rx_pkts)
                    tx_pkts = int(tx_pkts)
                    log.info("Tx packets are %d and Rx packets are %d "%(tx_pkts,rx_pkts))
                    stats = verify_stats_without_acl(rx_pkts, tx_pkts, traffic_tolerance)
                    if stats:
                        log.info("initial traffic is passed without ACL")
                    else:
                        log.error("initial traffic is failed without ACL")
                        self.failed(goto=['cleanup'])
                log.info("removing the traffice streams")
                try:
                    for id in stream_ids[handle_tx] :
                        result = spirent.sth.traffic_config(port_handle=handle_tx, mode='reset',stream_id=id)
                        log.info('result %s' % result)
                        log.info('Traffic removed')
                except Exception as e:
                    log.error('Failed to remove the traffic streams: %e ' % e)
                    self.failed(goto=['cleanup'])

class L2aclPositive_Single_ACE_Match(aetest.Testcase):
    @aetest.loop(ids = ['single_ace_match'])
    @aetest.test
    def tc_setup(self):
        intf_mode = self.script_args['intf_mode']
        acl_name = self.section.id
        Single_ACE_Match = Single_ACE_Match_dic()
        port_data = self.script_args['port_data']
        uut = self.script_args['uut']
        self.script_args['unconfig'] = ""
        extra_args = dict()
        streams = list(Single_ACE_Match['stream'].keys())
        uut_name = self.script_args['uut_name']
        interface = port_data[uut_name]['neighbors']['TGN-SPIRENT'][1]['interface']['name']
        acl_list = Single_ACE_Match['ace_list']
        seq_list = dict()
        seq_list['seq'] = dict()
        stream_ids = dict()
        traffic_tolerance = 0.2
        pdb.set_trace()
        keylist = list(Single_ACE_Match['stream'].keys())
        for i in keylist:
            #i = str(i)
            if i == 'params':
                continue
            seq = Single_ACE_Match['stream'][i]['seq']  # 10 20 30 40 implicit
            seq_list['seq'][i] = seq  # 10 20 30 40 implicit i = 1,2,3,4
        intf_mode = self.script_args['intf_mode']
        #ForkedPdb().set_trace()
        (xcon_res, xcon_msg) = check_xc_state(uut, "XCON")
        if xcon_res:
            log.info("XCONECT is UP")
            log.info(xcon_msg)
        else:
            log.error("XCONEECT is not up %s" % xcon_msg)
            self.failed(goto=['cleanup'])
        conf = '''ethernet-services access-list %s
                 %s ''' %(acl_name, acl_list)
        try:
            uut.config(conf)
        except Exception as e:
            log.error("Cant load config, failed as %s" % e)
        log.info("Clear interface counters before running traffic")
        try:
            uut.execute("clear counters")
        except Exception as e:
            log.error('Failed to clear interface counters : %s ' % e)
            self.failed()
        tgen = self.script_args['tgen_ip_var']
        for direction in ['ingress']:
            failure_hex = 0
            if (direction == 'ingress'):
                handle_tx = self.script_args['tgen_hdls'][0]
                handle_rx = self.script_args['tgen_hdls'][1]
            else:
                handle_tx = self.script_args['tgen_hdls'][1]
                handle_rx = self.script_args['tgen_hdls'][0]
            strem_details = dict()
            stream_ids[handle_tx] = []
            tgen_pkt_rate = 10000
            #ForkedPdb().set_trace()
            handle = [handle_tx,handle_rx]
            try :
                result = spirent.sth.traffic_config(port_handle=handle, mode='reset')
                log.info('result %s' % result)
                log.info('Traffic removed')
            except Exception as e:
                log.error('Failed to remove the traffic streams: %e '%e)
                self.failed(goto=['cleanup'])
            x = 1
            #ForkedPdb().set_trace()
            for i in streams :
                i = int(i)
                params = list(Single_ACE_Match['stream'][i]['params'].keys())
                if 'mac_src' not in params:
                    Single_ACE_Match['stream'][i]['params']['mac_src'] = 'aa:bb:cc:dd:ee:ff'
                if 'mac_dst' not in params:
                    Single_ACE_Match['stream'][i]['params']['mac_dst'] = 'ff:ee:dd:cc:bb:aa'
                if 'l3_protocol' not in params:
                    Single_ACE_Match['stream'][i]['params']['l3_protocol'] = 'ipv4'
                if 'vlan_id' not in params:
                    Single_ACE_Match['stream'][i]['params']['vlan_id'] = '100'
                extra_args = Single_ACE_Match['stream'][i]['params']
                #ForkedPdb().set_trace()
                try:
                    trafficList = spirent.sth.traffic_config(inter_stream_gap_unit='bytes',
                                                             #mac_src_step=1,
                                                             ip_src_mode='fixed',
                                                             l2_encap='ethernet_ii_vlan',
                                                             mac_src_mode='fixed',
                                                             length_mode='fixed',
                                                             #mac_dst_step=1,
                                                             rate_pps=tgen_pkt_rate,
                                                             ip_dst_mode='fixed',
                                                             mac_dst_mode='fixed',
                                                             #l3_protocol='ipv4',
                                                             #mac_dst=Single_ACE_Match['stream'][i]['params']['mac_dst'],
                                                             enable_stream_only_gen=0,
                                                             ip_ttl=64,
                                                             inter_stream_gap='116.0',
                                                             mode='create',
                                                             frame_size=pkt_size,
                                                             transmit_mode='continuous',
                                                             pkts_per_burst=pkts_per_burst,
                                                             #mac_src=streams[i]['params']['mac_src'],
                                                             #vlan_id=streams[i]['params']['vlan_id'],
                                                             #vlan_user_priority = streams[i]['params']['vlan_user_priority'],
                                                             # vlan_tpid:'33024',
                                                             port_handle=handle_tx,
                                                             # port_handle=handle,
                                                             enable_stream=0,
                                                             **extra_args
                                                             )
                    stream_ids[handle_tx].append(trafficList['stream_id'])
                    self.script_args['stream_ids'] = stream_ids
                    #ForkedPdb().set_trace()
                except Exception as e:
                    log.error(' sth.traffic_config for %s Failed trafficconfig_result:%s error: %s' %
                              (tgen, str(trafficList), e))
                    log.error('sth.traffic_config for Failed trafficconfig_result: %s ' % e)
                    self.failed(goto=['cleanup'])
            LOC = self.script_args['LOC']
            #ForkedPdb().set_trace()
            if intf_mode == 'interface':
                try:
                    conf_str = '''
                    interface %s
                    ethernet-services access-group %s %s
                    ''' % (interface, acl_name,direction)
                    uut.config(conf_str)
                    noconfig = """
                    interface %s
                    no ethernet-services access-group %s %s
                    root
                    no ethernet-services access-list %s
                    """ % (interface, acl_name,direction,acl_name)
                    self.script_args['unconfig'] += noconfig
                except Exception as e:
                    log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface, acl_name,e))
                    self.failed(goto=['cleanup'])
            elif intf_mode == 'subinterface':
                try:
                    conf_str = '''
                    interface %s l2transport
                    ethernet-services access-group %s %s '''% (interface + ".100", acl_name,direction)
                    noconfig = """
                        interface %s l2transport
                        no ethernet-services access-group %s %s
                        root
                        no ethernet-services access-list %s
                        """ % (interface + ".100", acl_name, direction, acl_name)
                    self.script_args['unconfig'] += noconfig
                    uut.config(conf_str)
                except Exception as e:
                    log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                    self.failed(goto=['cleanup'])
            for loc in LOC:
                clera_acl = ("clear access-list ethernet-services %s hardware %s location %s" % (acl_name, direction, loc+"/CPU0"))
                try:
                    uut.execute(clera_acl)
                except Exception as e:
                    log.error('Failed to clear ES ACL Counters : %s ' % e)
                    self.failed(goto=['cleanup'])

            log.info("starting the traffic")
            #ForkedPdb().set_trace()
            # with self.steps.start("Clear stats before starting the traffic") as step:
            log.info("Clear interface counters before running traffic")
            try:
                uut.execute("clear counters")
            except Exception as e:
                log.error('Failed to clear interface counters : %s ' % e)
                self.failed(goto=['cleanup'])
            log.info("Clear stats before starting the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                log.info('Traffic clear status : %s' % result['status'])
            except Exception as e:
                log.error('Failed to clear port counters: %s ' % e)
                self.failed(goto=['cleanup'])

            # with self.steps.start("Start the capture to get the capure packets") as step:
            log.info("Starting the traffic for 7secs")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
            except Exception as e:
                log.error('Failed to start traffic: ' % e)
                failure_hex += 1
                # self.failed()
                time.sleep(7)
            log.info("stoping the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                log.info("Poling: STC to see if traffic has stopped")
            except Exception as e:
                log.error('Failed to stop the  traffic: ' % e)
            log.info("cheching the traffic stats and verifying the TX and RX packets")
            try:
                stats_list = spirent.sth.traffic_stats(port_handle = handle_tx, mode='streams',
                                                       rx_port_handle='all', )
            except Exception as e:
                log.error('Failed collect the stats and hence verification got failed for the traffic: %s' % e)
                self.failed(goto=['cleanup'])
                failure_hex += 1
                # Get the TGN TX RX pkt count
            for stream in stream_ids[handle_tx]:
                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                    rx_pkts = 0
                else:
                    rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                    tx_pkts = 0
                else:
                    tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                rx_pkts = int(rx_pkts)
                tx_pkts = int(tx_pkts)
                #ForkedPdb().set_trace()
                if tx_pkts == 0:
                    log.info("Tx Packets are 0")
                    self.failed(goto=['cleanup'])
                seq = str(seq_list['seq'][x])
                x = x+1
                stats = verify_stats(uut, tx_pkts, rx_pkts, seq, acl_name, direction, loc, traffic_tolerance,
                                     stream)
                if stats:
                    log.info(
                        "traffic and ACL deny and permit is working fine with %s ACL with seq %s" % (acl_name, seq))
                else:
                    log.error("traffic and ACL deny and permit is not working fine with %s ACL with seq %s" % (
                    acl_name, seq))
                    self.failed(goto=['cleanup'])
            log.info("Removing the ACL and Checking the traffic")
            if intf_mode == 'interface':
                try:
                    conf_str = '''
                    interface %s
                    no ethernet-services access-group %s %s
                    root
                    no ethernet-services access-list %s
                    ''' % (interface, acl_name, direction, acl_name)
                    uut.config(conf_str)
                except Exception as e:
                    log.error('Failed to remove ES ACL %s on interface %s  : %s ' % (interface, acl_name, e))
                    self.failed(goto=['cleanup'])
            elif intf_mode == 'subinterface':
                try:
                    conf_str = '''
                    interface %s
                    no ethernet-services access-group %s %s
                    root
                    no ethernet-services access-list %s ''' % (interface + ".100", acl_name, direction, acl_name)
                    uut.config(conf_str)
                except Exception as e:
                    log.error('Failed to remove ES ACL %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                    self.failed(goto=['cleanup'])
            log.info("starting the traffic")
            #ForkedPdb().set_trace()
            # with self.steps.start("Clear stats before starting the traffic") as step:
            log.info("Clear stats before starting the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                log.info('Traffic clear status : %s' % result['status'])
            except Exception as e:
                log.error('Failed to clear port counters: %s ' % e)
                self.failed(goto=['cleanup'])
            log.info("Starting the traffic for 7secs")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
            except Exception as e:
                log.error('Failed to start traffic: ' % e)
                self.failed(goto=['cleanup'])
            time.sleep(7)
            log.info("stoping the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                log.info("Poling: STC to see if traffic has stopped")
            except Exception as e:
                log.error('Failed to stop the  traffic: ' % e)
                self.failed(goto=['cleanup'])
            log.info("cheching the traffic stats and verifying the TX and RX packets")
            try:
                stats_list = spirent.sth.traffic_stats(port_handle=handle_tx, mode='streams',
                                                       rx_port_handle='all', )
            except Exception as e:
                log.error('Failed collect the stats and hence verification got failed for the traffic %s: ' % e)
                self.failed(goto=['cleanup'])
            for stream in stream_ids[handle_tx]:
                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                    rx_pkts = 0
                else:
                    rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                    tx_pkts = 0
                else:
                    tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                rx_pkts = int(rx_pkts)
                tx_pkts = int(tx_pkts)
                stats = verify_stats_without_acl(rx_pkts, tx_pkts, traffic_tolerance)
                if stats:
                    log.info("traffic is passed after removing the ACL")
                else:
                    log.error("Traffic failed with ACL is removed")
                    self.failed(goto=['cleanup'])
            try:
                for id in stream_ids[handle_tx]:
                    result = spirent.sth.traffic_config(port_handle=handle_tx, mode='reset', stream_id=id)
                    log.info('result %s' % result)
                    log.info('Traffic removed')
            except Exception as e:
                log.error('Failed to remove the traffic streams: %e ' % e)
                self.failed(goto=['cleanup'])
    @aetest.test
    def tc_check_trace_crash(self):
        failure = 0
        # need some clarification
        uut = self.script_args['uut']
        log.info("Verification of show logging and show context location all")
        try:
            res = verify_show_logging_context(uut)
            if not res:
                log.error('Crash Check Failed')
                self.failed()
        except Exception as e:
            log.error(
                'Verification of show logging and show context location all failed in the router %s as %s' % (uut, e))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        uut = self.script_args['uut']
        try:
            log.info("Reset the port configuration to default")
            log.info("removing ACL  configuration")
            conf = self.script_args['unconfig']
            uut.config(conf)
        except Exception as e:
            log.error('Test Clean up is failed: %s ' % e)
            self.failed()

class L2aclPositive_BasicACL(aetest.Testcase):
    basic_acls = basic_acls_format()
    acl_name_name = list(basic_acls.keys())
    @aetest.loop(ids = ['format-1', 'format-2', 'format-3'])
    @aetest.test
    def tc_setup(self):
        acl_name = self.section.id
        uut_name = self.script_args['uut_name']
        basic_acl = basic_acls_format()
        port_data = self.script_args['port_data']
        uut = self.script_args['uut']
        self.script_args['unconfig'] = ""
        extra_args = dict()
        streams = list(basic_acl[acl_name]['stream'].keys())
        interface = port_data[uut_name]['neighbors']['TGN-SPIRENT'][1]['interface']['name']
        acl_list = basic_acl[acl_name]['ace_list']
        seq_list = dict()
        seq_list['seq'] = dict()
        stream_ids = dict()

        traffic_tolerance = 0.2
        keylist = list(basic_acl[acl_name]['stream'].keys())
        for i in keylist:
            if i == 'params':
                continue
            seq = basic_acl[acl_name]['stream'][i]['seq']  # 10 20 30 40 implicit
            seq_list['seq'][i] = seq  # 10 20 30 40 implicit i = 1,2,3,4
        intf_mode = self.script_args['intf_mode']
        (xcon_res, xcon_msg) = check_xc_state(uut, "XCON")
        if xcon_res:
            log.info("XCONECT is UP")
            log.info(xcon_msg)
        else:
            log.error("XCONEECT is not up %s" % xcon_msg)
            self.failed(goto=['cleanup'])
        conf = '''ethernet-services access-list %s
                 %s ''' %(acl_name, acl_list)
        try:
            uut.config(conf)
        except Exception as e:
            log.error("Cant load config, failed as %s" % e)
        log.info("Clear interface counters before running traffic")
        try:
            uut.execute("clear counters")
        except Exception as e:
            log.error('Failed to clear interface counters : %s ' % e)
            self.failed()
        tgen = self.script_args['tgen_ip_var']
        for direction in ['ingress']:
            failure_hex = 0
            if (direction == 'ingress'):
                handle_tx = self.script_args['tgen_hdls'][0]
                handle_rx = self.script_args['tgen_hdls'][1]
            else:
                handle_tx = self.script_args['tgen_hdls'][1]
                handle_rx = self.script_args['tgen_hdls'][0]
            strem_details = dict()
            stream_ids[handle_tx] = []
            tgen_pkt_rate = 10000
            handle = [handle_tx,handle_rx]
            try :
                result = spirent.sth.traffic_config(port_handle=handle, mode='reset')
                log.info('result %s' % result)
                log.info('Traffic removed')
            except Exception as e:
                log.error('Failed to remove the traffic streams: %e '%e)
                self.failed(goto=['cleanup'])
            j = 1
            for i in streams :
                i = int(i)
                params = list(basic_acl[acl_name]['stream'][i]['params'].keys())
                if 'mac_src' not in params:
                    basic_acl[acl_name]['stream'][i]['params']['mac_src'] = 'aa:bb:cc:dd:ee:ff'
                if 'mac_dst' not in params:
                    basic_acl[acl_name]['stream'][i]['params']['mac_dst'] = 'ff:ee:dd:cc:bb:aa'
                if 'l3_protocol' not in params:
                    basic_acl[acl_name]['stream'][i]['params']['l3_protocol'] = 'ipv4'
                if 'vlan_id' not in params:
                    basic_acl[acl_name]['stream'][i]['params']['vlan_id'] = '100'
                extra_args = basic_acl[acl_name]['stream'][i]['params']
                try:
                    trafficList = spirent.sth.traffic_config(inter_stream_gap_unit='bytes',
                                                             #mac_src_step=1,
                                                             ip_src_mode='fixed',
                                                             l2_encap='ethernet_ii_vlan',
                                                             mac_src_mode='fixed',
                                                             length_mode='fixed',
                                                             #mac_dst_step=1,
                                                             rate_pps=tgen_pkt_rate,
                                                             ip_dst_mode='fixed',
                                                             mac_dst_mode='fixed',
                                                             enable_stream_only_gen=0,
                                                             ip_ttl=64,
                                                             inter_stream_gap='116.0',
                                                             mode='create',
                                                             frame_size=pkt_size,
                                                             transmit_mode='continuous',
                                                             pkts_per_burst=pkts_per_burst,
                                                             port_handle=handle_tx,
                                                             enable_stream=0,
                                                             **extra_args
                                                             )
                    stream_ids[handle_tx].append(trafficList['stream_id'])
                    self.script_args['stream_ids'] = stream_ids
                except Exception as e:
                    log.error(' sth.traffic_config for %s Failed trafficconfig_result:%s error: %s' %
                              (tgen, str(trafficList), e))
                    log.error('sth.traffic_config for Failed trafficconfig_result: %s ' % e)
                    self.failed(goto=['cleanup'])
            LOC = self.script_args['LOC']
            if intf_mode == 'interface':
                try:
                    conf_str = '''
                    interface %s
                    ethernet-services access-group %s %s
                    ''' % (interface, acl_name,direction)
                    uut.config(conf_str)
                    noconfig = """
                    interface %s
                    no ethernet-services access-group %s %s
                    root
                    no ethernet-services access-list %s
                    """ % (interface, acl_name,direction,acl_name)
                    self.script_args['unconfig'] += noconfig
                except Exception as e:
                    log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface, acl_name,e))
                    self.failed(goto=['cleanup'])
            elif intf_mode == 'subinterface':
                try:
                    conf_str = '''
                    interface %s l2transport
                    ethernet-services access-group %s %s '''% (interface + ".100", acl_name,direction)
                    noconfig = """
                        interface %s l2transport
                        no ethernet-services access-group %s %s
                        root
                        no ethernet-services access-list %s
                        """ % (interface + ".100", acl_name, direction, acl_name)
                    self.script_args['unconfig'] += noconfig
                    uut.config(conf_str)
                except Exception as e:
                    log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                    self.failed(goto=['cleanup'])
            for loc in LOC:
                clera_acl = ("clear access-list ethernet-services %s hardware %s location %s" % (acl_name, direction, loc+"/CPU0"))
                try:
                    uut.execute(clera_acl)
                except Exception as e:
                    log.error('Failed to clear ES ACL Counters : %s ' % e)
                    self.failed(goto=['cleanup'])

            log.info("starting the traffic")
            log.info("Clear interface counters before running traffic")
            try:
                uut.execute("clear counters")
            except Exception as e:
                log.error('Failed to clear interface counters : %s ' % e)
                self.failed(goto=['cleanup'])
            log.info("Clear stats before starting the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                log.info('Traffic clear status : %s' % result['status'])
            except Exception as e:
                log.error('Failed to clear port counters: %s ' % e)
                self.failed(goto=['cleanup'])

            # with self.steps.start("Start the capture to get the capure packets") as step:
            log.info("Starting the traffic for 7secs")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
            except Exception as e:
                log.error('Failed to start traffic: ' % e)
                failure_hex += 1
                # self.failed()
                time.sleep(7)
            log.info("stoping the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                log.info("Poling: STC to see if traffic has stopped")
            except Exception as e:
                log.error('Failed to stop the  traffic: ' % e)
            log.info("cheching the traffic stats and verifying the TX and RX packets")
            try:
                stats_list = spirent.sth.traffic_stats(port_handle = handle_tx, mode='streams',
                                                       rx_port_handle='all', )
            except Exception as e:
                log.error('Failed collect the stats and hence verification got failed for the traffic:: %s ' % e)
                self.failed(goto=['cleanup'])
                failure_hex += 1
                # Get the TGN TX RX pkt count
            for stream in stream_ids[handle_tx]:
                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                    rx_pkts = 0
                else:
                    rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                    tx_pkts = 0
                else:
                    tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                rx_pkts = int(rx_pkts)
                tx_pkts = int(tx_pkts)
                seq = str(seq_list['seq'][j])
                j = j+1
                stats = verify_stats(uut, tx_pkts, rx_pkts, seq, acl_name, direction, loc, traffic_tolerance,
                                     stream)
                if stats:
                    log.info("traffic and ACL deny and permit is working fine with %s ACL with seq %s" % (acl_name,seq))
                else:
                    log.error("traffic and ACL deny and permit is not working fine with %s ACL with seq %s" % (acl_name,seq))
                    self.failed(goto=['cleanup'])
            log.info("Removing the ACL and Checking the traffic")
            if intf_mode == 'interface':
                try:
                    conf_str = '''
                    interface %s
                    no ethernet-services access-group %s %s
                    root
                    no ethernet-services access-list %s
                    ''' % (interface, acl_name, direction, acl_name)
                    uut.config(conf_str)
                except Exception as e:
                    log.error('Failed to remove ES ACL %s on interface %s  : %s ' % (interface, acl_name, e))
                    self.failed(goto=['cleanup'])
            elif intf_mode == 'subinterface':
                try:
                    conf_str = '''
                    interface %s
                    no ethernet-services access-group %s %s
                    root
                    no ethernet-services access-list %s ''' % (interface + ".100", acl_name, direction, acl_name)
                    uut.config(conf_str)
                except Exception as e:
                    log.error('Failed to remove ES ACL %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                    self.failed(goto=['cleanup'])
            log.info("starting the traffic")
            #ForkedPdb().set_trace()
            # with self.steps.start("Clear stats before starting the traffic") as step:
            log.info("Clear stats before starting the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                log.info('Traffic clear status : %s' % result['status'])
            except Exception as e:
                log.error('Failed to clear port counters: %s ' % e)
                self.failed(goto=['cleanup'])
            log.info("Starting the traffic for 7secs")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
            except Exception as e:
                log.error('Failed to start traffic: ' % e)
                self.failed(goto=['cleanup'])
            time.sleep(7)
            log.info("stoping the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                log.info("Poling: STC to see if traffic has stopped")
            except Exception as e:
                log.error('Failed to stop the  traffic: ' % e)
                self.failed(goto=['cleanup'])
            log.info("cheching the traffic stats and verifying the TX and RX packets")
            try:
                stats_list = spirent.sth.traffic_stats(port_handle=handle_tx, mode='streams',
                                                       rx_port_handle='all', )
            except Exception as e:
                log.error('Failed collect the stats and hence verification got failed for the traffic:: %s ' % e)
                self.failed(goto=['cleanup'])
            for stream in stream_ids[handle_tx]:
                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                    rx_pkts = 0
                else:
                    rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                    tx_pkts = 0
                else:
                    tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                rx_pkts = int(rx_pkts)
                tx_pkts = int(tx_pkts)
                stats = verify_stats_without_acl(rx_pkts, tx_pkts, traffic_tolerance)
                if stats:
                    log.info("traffic is passed after removing the ACL")
                else:
                    log.error("Traffic failed with ACL is removed")
                    self.failed(goto=['cleanup'])
            try:
                for id in stream_ids[handle_tx]:
                    result = spirent.sth.traffic_config(port_handle=handle_tx, mode='reset', stream_id=id)
                    log.info('result %s' % result)
                    log.info('Traffic removed')
            except Exception as e:
                log.error('Failed to remove the traffic streams: %e ' % e)
                self.failed(goto=['cleanup'])

    @aetest.test
    def tc_check_trace_crash(self):
        failure = 0
        # need some clarification
        uut = self.script_args['uut']
        log.info("Verification of show logging and show context location all")
        try:
            res = verify_show_logging_context(uut)
            if not res:
                log.error('Crash Check Failed')
                self.failed()
        except Exception as e:
            log.error(
                'Verification of show logging and show context location all failed in the router %s as %s' % (uut, e))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        uut = self.script_args['uut']
        try:
            log.info("Reset the port configuration to default")
            log.info("removing ACL  configuration")
            conf = self.script_args['unconfig']
            uut.config(conf)
        except Exception as e:
            log.error('Test Clean up is failed: %s ' % e)
            self.failed()



class L2aclPositive_acl_edits(aetest.Testcase):
    @aetest.loop(
        ids=[ 'value-edit', 'field-edit-no-format-change', 'field-edit-format-change', 'ace-insert-no-format-change',
             'ace-insert-format-change', 'ace-delete', 'multiple-ace-edits'])
    @aetest.test
    #@aetest.test.loop(ids = ['value-edit'])
    def tc_setup(self):
        intf_mode = self.script_args['intf_mode']
        acl_name = self.section.id
        acl_edits = acl_edits_dic()
        port_data = self.script_args['port_data']
        self.script_args['unconfig'] = ""
        uut = self.script_args['uut']
        extra_args = dict()
        uut_name = self.script_args['uut_name']
        interface = port_data[uut_name]['neighbors']['TGN-SPIRENT'][1]['interface']['name']
        traffic_tolerance = 0.2
        stream_ids = dict()
        intf_mode = self.script_args['intf_mode']
        (xcon_res, xcon_msg) = check_xc_state(uut, "XCON")
        if xcon_res:
            log.info("XCONECT is UP")
            log.info(xcon_msg)
        else:
            log.error("XCONEECT is not up %s" % xcon_msg)
            self.failed(goto=['cleanup'])
        log.info("Clear interface counters before running traffic")
        try:
            uut.execute("clear counters")
        except Exception as e:
            log.error('Failed to clear interface counters : %s ' % e)
            self.failed()
        tgen = self.script_args['tgen_ip_var']
        for direction in ['ingress']:
            failure_hex = 0
            if (direction == 'ingress'):
                handle_tx = self.script_args['tgen_hdls'][0]
                handle_rx = self.script_args['tgen_hdls'][1]
            else:
                handle_tx = self.script_args['tgen_hdls'][1]
                handle_rx = self.script_args['tgen_hdls'][0]
            strem_details = dict()
            stream_ids[handle_tx] = []
            tgen_pkt_rate = 10000
            #ForkedPdb().set_trace()
            handle = [handle_tx,handle_rx]
            streams = list(acl_edits[acl_name]['stream'].keys())
            for i in streams :
                i = int(i)
                params = list(acl_edits[acl_name]['stream'][i]['params'].keys())
                if 'mac_src' not in params:
                    acl_edits[acl_name]['stream'][i]['params']['mac_src'] = 'aa:bb:cc:dd:ee:ff'
                if 'mac_dst' not in params:
                    acl_edits[acl_name]['stream'][i]['params']['mac_dst'] = 'ff:ee:dd:cc:bb:aa'
                if 'l3_protocol' not in params:
                    acl_edits[acl_name]['stream'][i]['params']['l3_protocol'] = 'ipv4'
                if 'vlan_id' not in params:
                    acl_edits[acl_name]['stream'][i]['params']['vlan_id'] = '100'
                extra_args = acl_edits[acl_name]['stream'][i]['params']
                #ForkedPdb().set_trace()
                try:
                    trafficList = spirent.sth.traffic_config(inter_stream_gap_unit='bytes',
                                                             #mac_src_step=1,
                                                             ip_src_mode='fixed',
                                                             l2_encap='ethernet_ii_vlan',
                                                             mac_src_mode='fixed',
                                                             length_mode='fixed',
                                                             #mac_dst_step=1,
                                                             rate_pps=tgen_pkt_rate,
                                                             ip_dst_mode='fixed',
                                                             mac_dst_mode='fixed',
                                                             #l3_protocol='ipv4',
                                                             #mac_dst=acl_edits[acl_name]['stream'][i]['params']['mac_dst'],
                                                             enable_stream_only_gen=0,
                                                             ip_ttl=64,
                                                             inter_stream_gap='116.0',
                                                             mode='create',
                                                             frame_size=pkt_size,
                                                             transmit_mode='continuous',
                                                             pkts_per_burst=pkts_per_burst,
                                                             #mac_src=streams[i]['params']['mac_src'],
                                                             #vlan_id=streams[i]['params']['vlan_id'],
                                                             #vlan_user_priority = streams[i]['params']['vlan_user_priority'],
                                                             # vlan_tpid:'33024',
                                                             port_handle=handle_tx,
                                                             # port_handle=handle,
                                                             enable_stream=0,
                                                             **extra_args
                                                             )
                    stream_ids[handle_tx].append(trafficList['stream_id'])
                    self.script_args['stream_ids'] = stream_ids
                    #ForkedPdb().set_trace()
                except Exception as e:
                    log.error(' sth.traffic_config for %s Failed trafficconfig_result:%s error: %s' %
                              (tgen, str(trafficList), e))
                    log.error('sth.traffic_config for Failed trafficconfig_result: %s ' % e)
                    self.failed(goto=['cleanup'])
            LOC = self.script_args['LOC']
            for acl_id in acl_edits[acl_name]['acl'].keys():
                j = 1
                acl_list = acl_edits[acl_name]['acl'][acl_id]['ace_list']
                conf = '''ethernet-services access-list %s
                 %s ''' %(acl_name, acl_list)
                try:
                    uut.config(conf)
                except Exception as e:
                    log.error("Cant load config, failed as %s" % e)
                if intf_mode == 'interface':
                    try:
                        conf_str = '''
                        interface %s
                        ethernet-services access-group %s %s
                        ''' % (interface, acl_name,direction)
                        uut.config(conf_str)
                        noconfig = """
                        interface %s
                        no ethernet-services access-group %s %s
                        root
                        no ethernet-services access-list %s
                        """ % (interface, acl_name,direction,acl_name)
                        self.script_args['unconfig'] +=noconfig
                    except Exception as e:
                        log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface, acl_name,e))
                        self.failed(goto=['cleanup'])
                elif intf_mode == 'subinterface':
                    try:
                        conf_str = '''
                            interface %s
                            ethernet-services access-group %s %s '''% (interface + ".100", acl_name,direction)
                        noconfig = """
                            interface %s l2transport
                            no ethernet-services access-group %s %s
                            root
                            no ethernet-services access-list %s
                            """ % (interface + ".100", acl_name, direction, acl_name)
                        self.script_args['unconfig'] += noconfig
                        uut.config(conf_str)
                    except Exception as e:
                        log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                        self.failed(goto=['cleanup'])
                for loc in LOC:
                    log.info("Clearing  ES ACL Counters counters before running traffic")
                    clera_acl = ("clear access-list ethernet-services %s hardware %s location %s" % (acl_name, direction, loc+"/CPU0"))
                    try:
                        uut.execute(clera_acl)
                    except Exception as e:
                        log.error('Failed to clear ES ACL Counters : %s ' % e)
                        self.failed(goto=['cleanup'])
                seq_list = dict()
                seq_list['seq'] = dict()

                keylist = list(acl_edits[acl_name]['acl'][acl_id]['stream'].keys())
                for i in keylist:
                    #i = str(i)
                    if i == 'params':
                        continue
                    seq = acl_edits[acl_name]['acl'][acl_id]['stream'][i]['seq']  # 10 20 30 40 implicit
                    seq_list['seq'][i] = seq  # 10 20 30 40 implicit i = 1,2,3,4
                log.info("starting the traffic")
                log.info("Clear interface counters before running traffic")
                try:
                    uut.execute("clear counters")
                except Exception as e:
                    log.error('Failed to clear interface counters : %s ' % e)
                    self.failed(goto=['cleanup'])
                log.info("Clear stats before starting the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                    log.info('Traffic clear status : %s' % result['status'])
                except Exception as e:
                    log.error('Failed to clear port counters: %s ' % e)
                    self.failed(goto=['cleanup'])

                # with self.steps.start("Start the capture to get the capure packets") as step:
                log.info("Starting the traffic for 7secs")
                #ForkedPdb().set_trace()
                try:
                    result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
                except Exception as e:
                    log.error('Failed to start traffic: ' % e)
                    failure_hex += 1
                    # self.failed()
                    time.sleep(7)
                log.info("stoping the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                    log.info("Poling: STC to see if traffic has stopped")
                except Exception as e:
                    log.error('Failed to stop the  traffic: ' % e)
                log.info("cheching the traffic stats and verifying the TX and RX packets")
                try:
                    stats_list = spirent.sth.traffic_stats(port_handle = handle_tx, mode='streams',
                                                           rx_port_handle='all', )
                except Exception as e:
                    log.error('Failed collect the stats and hence verification got failed for the traffic: : %s' % e)
                    self.failed(goto=['cleanup'])
                    failure_hex += 1
                    # Get the TGN TX RX pkt count
                for stream in stream_ids[handle_tx]:
                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                        rx_pkts = 0
                    else:
                        rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                        tx_pkts = 0
                    else:
                        tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                    rx_pkts = int(rx_pkts)
                    tx_pkts = int(tx_pkts)
                    #ForkedPdb().set_trace()
                    #ForkedPdb().set_trace()
                    if tx_pkts == 0:
                        log.info("Tx Packets are 0")
                        self.failed(goto=['cleanup'])
                    seq = str(seq_list['seq'][j])
                    j = j+1
                    stats = verify_stats(uut, tx_pkts, rx_pkts, seq, acl_name, direction, loc, traffic_tolerance,
                                         stream)
                    if stats:
                        log.info("traffic and ACL deny and permit is working fine with %s ACL with seq %s" % (acl_name, seq))
                    else:
                        log.error("traffic and ACL deny and permit is not working fine with %s ACL with seq %s" % (acl_name, seq))
                        self.failed(goto=['cleanup'])

            log.info("Removing the ACL and Checking the traffic")
            if intf_mode == 'interface':
                try:
                    conf_str = '''
                    interface %s
                    no ethernet-services access-group %s %s
                    root
                    ''' % (interface, acl_name, direction)
                    uut.config(conf_str)
                except Exception as e:
                    log.error('Failed to remove ES ACL %s on interface %s  : %s ' % (interface, acl_name, e))
                    self.failed(goto=['cleanup'])
            elif intf_mode == 'subinterface':
                try:
                    conf_str = '''
                    interface %s
                    no ethernet-services access-group %s %s''' % (interface + ".100", acl_name, direction)
                    uut.config(conf_str)
                except Exception as e:
                    log.error('Failed to remove ES ACL %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                    self.failed(goto=['cleanup'])
            log.info("starting the traffic")
            # ForkedPdb().set_trace()
            # with self.steps.start("Clear stats before starting the traffic") as step:
            log.info("Clear stats before starting the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                log.info('Traffic clear status : %s' % result['status'])
            except Exception as e:
                log.error('Failed to clear port counters: %s ' % e)
                self.failed(goto=['cleanup'])
            log.info("Starting the traffic for 7secs")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
            except Exception as e:
                log.error('Failed to start traffic: ' % e)
                self.failed(goto=['cleanup'])
            time.sleep(7)
            log.info("stoping the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                log.info("Poling: STC to see if traffic has stopped")
            except Exception as e:
                log.error('Failed to stop the  traffic: ' % e)
                self.failed(goto=['cleanup'])
            log.info("cheching the traffic stats and verifying the TX and RX packets")
            try:
                stats_list = spirent.sth.traffic_stats(port_handle=handle_tx, mode='streams',
                                                       rx_port_handle='all', )
            except Exception as e:
                log.error('Failed collect the stats and hence verification got failed for the traffic:: %s ' % e)
                self.failed(goto=['cleanup'])
            for stream in stream_ids[handle_tx]:
                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                    rx_pkts = 0
                else:
                    rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                    tx_pkts = 0
                else:
                    tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                rx_pkts = int(rx_pkts)
                tx_pkts = int(tx_pkts)
                stats = verify_stats_without_acl(rx_pkts, tx_pkts, traffic_tolerance)
                if stats:
                    log.info("traffic is passed after removing the ACL")
                else:
                    log.error("Traffic failed with ACL is removed")
                    self.failed(goto=['cleanup'])
            try:
                conf_str = '''
                no ethernet-services access-list %s
                ''' % (acl_name)
                uut.config(conf_str)
            except Exception as e:
                log.error('Failed to remove ES ACL %s on interface %s  : %s ' % (interface, acl_name, e))
                self.failed(goto=['cleanup'])
            try:
                for id in stream_ids[handle_tx]:
                    result = spirent.sth.traffic_config(port_handle=handle_tx, mode='reset', stream_id=id)
                    log.info('result %s' % result)
                    log.info('Traffic removed')
            except Exception as e:
                log.error('Failed to remove the traffic streams: %e ' % e)
                self.failed(goto=['cleanup'])

    @aetest.test
    def tc_check_trace_crash(self):
        failure = 0
        # need some clarification
        uut = self.script_args['uut']
        log.info("Verification of show logging and show context location all")
        try:
            res = verify_show_logging_context(uut)
            if not res:
                log.error('Crash Check Failed')
                self.failed()
        except Exception as e:
            log.error(
                'Verification of show logging and show context location all failed in the router %s as %s' % (uut, e))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        uut = self.script_args['uut']
        try:
            log.info("Reset the port configuration to default")
            log.info("removing ACL  configuration")
            conf = self.script_args['unconfig']
            uut.config(conf)
        except Exception as e:
            log.error('Test Clean up is failed: %s ' % e)
            self.failed()

class L2aclPositive_atomic_replace(aetest.Testcase):
    atomic_replace = atomic_replace_dic()
    acl_name_name = list(atomic_replace.keys())
    @aetest.loop(ids = ['acl_1','acl_2'])
    @aetest.test
    def tc_setup(self):
        intf_mode = self.script_args['intf_mode']
        acl_name = self.section.id
        atomic_replace = atomic_replace_dic()
        port_data = self.script_args['port_data']
        uut = self.script_args['uut']
        self.script_args['unconfig'] = ""
        uut_name = self.script_args['uut_name']
        extra_args = dict()
        interface = port_data[uut_name]['neighbors']['TGN-SPIRENT'][1]['interface']['name']
        traffic_tolerance = 0.2
        stream_ids = dict()
        intf_mode = self.script_args['intf_mode']
        (xcon_res, xcon_msg) = check_xc_state(uut, "XCON")
        if xcon_res:
            log.info("XCONECT is UP")
            log.info(xcon_msg)
        else:
            log.error("XCONEECT is not up %s" % xcon_msg)
            self.failed(goto=['cleanup'])
        log.info("Clear interface counters before running traffic")
        try:
            uut.execute("clear counters")
        except Exception as e:
            log.error('Failed to clear interface counters : %s ' % e)
            self.failed()
        tgen = self.script_args['tgen_ip_var']
        for direction in ['ingress']:
            failure_hex = 0
            if (direction == 'ingress'):
                handle_tx = self.script_args['tgen_hdls'][0]
                handle_rx = self.script_args['tgen_hdls'][1]
            else:
                handle_tx = self.script_args['tgen_hdls'][1]
                handle_rx = self.script_args['tgen_hdls'][0]
            strem_details = dict()
            stream_ids[handle_tx] = []
            tgen_pkt_rate = 10000
            #ForkedPdb().set_trace()
            handle = [handle_tx,handle_rx]
            j = 1
            streams = list(atomic_replace['stream'].keys())
            for i in streams :
                i = int(i)
                params = list(atomic_replace['stream'][i]['params'].keys())
                if 'mac_src' not in params:
                    atomic_replace['stream'][i]['params']['mac_src'] = 'aa:bb:cc:dd:ee:ff'
                if 'mac_dst' not in params:
                    atomic_replace['stream'][i]['params']['mac_dst'] = 'ff:ee:dd:cc:bb:aa'
                if 'l3_protocol' not in params:
                    atomic_replace['stream'][i]['params']['l3_protocol'] = 'ipv4'
                if 'vlan_id' not in params:
                    atomic_replace['stream'][i]['params']['vlan_id'] = '100'
                extra_args = atomic_replace['stream'][i]['params']
                #ForkedPdb().set_trace()
                try:
                    trafficList = spirent.sth.traffic_config(inter_stream_gap_unit='bytes',
                                                             #mac_src_step=1,
                                                             ip_src_mode='fixed',
                                                             l2_encap='ethernet_ii_vlan',
                                                             mac_src_mode='fixed',
                                                             length_mode='fixed',
                                                             #mac_dst_step=1,
                                                             rate_pps=tgen_pkt_rate,
                                                             ip_dst_mode='fixed',
                                                             mac_dst_mode='fixed',
                                                             #l3_protocol='ipv4',
                                                             #mac_dst=atomic_replace['stream'][i]['params']['mac_dst'],
                                                             enable_stream_only_gen=0,
                                                             ip_ttl=64,
                                                             inter_stream_gap='116.0',
                                                             mode='create',
                                                             frame_size=pkt_size,
                                                             transmit_mode='continuous',
                                                             pkts_per_burst=pkts_per_burst,
                                                             #mac_src=streams[i]['params']['mac_src'],
                                                             #vlan_id=streams[i]['params']['vlan_id'],
                                                             #vlan_user_priority = streams[i]['params']['vlan_user_priority'],
                                                             # vlan_tpid:'33024',
                                                             port_handle=handle_tx,
                                                             # port_handle=handle,
                                                             enable_stream=0,
                                                             **extra_args
                                                             )
                    stream_ids[handle_tx].append(trafficList['stream_id'])
                    self.script_args['stream_ids'] = stream_ids
                    #ForkedPdb().set_trace()
                except Exception as e:
                    log.error(' sth.traffic_config for %s Failed trafficconfig_result:%s error: %s' %
                              (tgen, str(trafficList), e))
                    log.error('sth.traffic_config for Failed trafficconfig_result: %s ' % e)
                    self.failed(goto=['cleanup'])
            LOC = self.script_args['LOC']
            #ForkedPdb().set_trace()
            if acl_name == 'acl_1':
                acl_id = 1
            else :
                acl_id = 2
            acl_list = atomic_replace['acl'][acl_id]['ace_list']
            #ForkedPdb().set_trace()
            conf = '''ethernet-services access-list %s
             %s ''' %(acl_name, acl_list)
            try:
                uut.config(conf)
            except Exception as e:
                log.error("Cant load config, failed as %s" % e)

            if intf_mode == 'interface':
                try:
                    conf_str = '''
                    interface %s
                    ethernet-services access-group %s %s
                    ''' % (interface, acl_name,direction)
                    uut.config(conf_str)
                    noconfig = """
                    interface %s
                    no ethernet-services access-group %s %s
                    root
                    no ethernet-services access-list %s
                    """ % (interface, acl_name,direction,acl_name)
                    self.script_args['unconfig'] +=noconfig
                except Exception as e:
                    log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface, acl_name,e))
                    self.failed(goto=['cleanup'])
            elif intf_mode == 'subinterface':
                try:
                    conf_str = '''
                    interface %s l2transport
                    ethernet-services access-group %s %s '''% (interface + ".100", acl_name,direction)
                    noconfig = """
                        interface %s l2transport
                        no ethernet-services access-group %s %s
                        root
                        no ethernet-services access-list %s
                        """ % (interface + ".100", acl_name, direction, acl_name)
                    self.script_args['unconfig'] += noconfig
                    uut.config(conf_str)
                except Exception as e:
                    log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                    self.failed(goto=['cleanup'])
            for loc in LOC:
                log.info("Clearing  ES ACL Counters counters before running traffic")
                clera_acl = ("clear access-list ethernet-services %s hardware %s location %s" % (acl_name, direction, loc+"/CPU0"))
                try:
                    uut.execute(clera_acl)
                except Exception as e:
                    log.error('Failed to clear ES ACL Counters : %s ' % e)
                    self.failed(goto=['cleanup'])
            seq_list = dict()
            seq_list['seq'] = dict()
            keylist = list(atomic_replace['acl'][acl_id]['stream'].keys())
            for i in keylist:
                #i = str(i)
                if i == 'params':
                    continue
                seq = atomic_replace['acl'][acl_id]['stream'][i]['seq']  # 10 20 30 40 implicit
                seq_list['seq'][i] = seq  # 10 20 30 40 implicit i = 1,2,3,4
            log.info("starting the traffic")
            log.info("Clear interface counters before running traffic")
            try:
                uut.execute("clear counters")
            except Exception as e:
                log.error('Failed to clear interface counters : %s ' % e)
                self.failed(goto=['cleanup'])
            log.info("Clear stats before starting the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                log.info('Traffic clear status : %s' % result['status'])
            except Exception as e:
                log.error('Failed to clear port counters: %s ' % e)
                self.failed(goto=['cleanup'])

            # with self.steps.start("Start the capture to get the capure packets") as step:
            log.info("Starting the traffic for 7secs")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
            except Exception as e:
                log.error('Failed to start traffic: ' % e)
                failure_hex += 1
                # self.failed()
                time.sleep(7)
            log.info("stoping the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                log.info("Poling: STC to see if traffic has stopped")
            except Exception as e:
                log.error('Failed to stop the  traffic: ' % e)
            log.info("cheching the traffic stats and verifying the TX and RX packets")
            try:
                stats_list = spirent.sth.traffic_stats(port_handle = handle_tx, mode='streams',
                                                       rx_port_handle='all', )
            except Exception as e:
                log.error('Failed collect the stats and hence verification got failed for the traffic:: %s ' % e)
                failure_hex += 1
                self.failed(goto=['cleanup'])
                # Get the TGN TX RX pkt count
            for stream in stream_ids[handle_tx]:
                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                    rx_pkts = 0
                else:
                    rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                    tx_pkts = 0
                else:
                    tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                rx_pkts = int(rx_pkts)
                tx_pkts = int(tx_pkts)
                #ForkedPdb().set_trace()
                if tx_pkts == 0:
                    log.info("Tx Packets are 0")
                    self.failed(goto=['cleanup'])
                seq = str(seq_list['seq'][j])
                j = j+1
                stats = verify_stats(uut, tx_pkts, rx_pkts, seq, acl_name, direction, loc, traffic_tolerance,
                                     stream)
                if stats:
                    log.info(
                        "traffic and ACL deny and permit is working fine with %s ACL with seq %s" % (acl_name, seq))
                else:
                    log.error("traffic and ACL deny and permit is not working fine with %s ACL with seq %s" % (
                    acl_name, seq))
                    self.failed(goto=['cleanup'])
            log.info("Removing the ACL and Checking the traffic")
            if intf_mode == 'interface':
                try:
                    conf_str = '''
                    interface %s
                    no ethernet-services access-group %s %s
                    root
                    no ethernet-services access-list %s
                    ''' % (interface, acl_name, direction, acl_name)
                    uut.config(conf_str)
                except Exception as e:
                    log.error('Failed to remove ES ACL %s on interface %s  : %s ' % (interface, acl_name, e))
                    self.failed(goto=['cleanup'])
            elif intf_mode == 'subinterface':
                try:
                    conf_str = '''
                    interface %s
                    no ethernet-services access-group %s %s
                    root
                    no ethernet-services access-list %s ''' % (interface + ".100", acl_name, direction, acl_name)
                    uut.config(conf_str)
                except Exception as e:
                    log.error('Failed to remove ES ACL %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                    self.failed(goto=['cleanup'])
            log.info("starting the traffic")
            # ForkedPdb().set_trace()
            # with self.steps.start("Clear stats before starting the traffic") as step:
            log.info("Clear stats before starting the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                log.info('Traffic clear status : %s' % result['status'])
            except Exception as e:
                log.error('Failed to clear port counters: %s ' % e)
                self.failed(goto=['cleanup'])
            log.info("Starting the traffic for 7secs")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
            except Exception as e:
                log.error('Failed to start traffic: ' % e)
                self.failed(goto=['cleanup'])
            time.sleep(7)
            log.info("stoping the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                log.info("Poling: STC to see if traffic has stopped")
            except Exception as e:
                log.error('Failed to stop the  traffic: ' % e)
                self.failed(goto=['cleanup'])
            log.info("cheching the traffic stats and verifying the TX and RX packets")
            try:
                stats_list = spirent.sth.traffic_stats(port_handle=handle_tx, mode='streams',
                                                       rx_port_handle='all', )
            except Exception as e:
                log.error('Failed collect the stats and hence verification got failed for the traffic:: %s ' % e)
                self.failed(goto=['cleanup'])
            for stream in stream_ids[handle_tx]:
                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                    rx_pkts = 0
                else:
                    rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                    tx_pkts = 0
                else:
                    tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                rx_pkts = int(rx_pkts)
                tx_pkts = int(tx_pkts)
                stats = verify_stats_without_acl(rx_pkts, tx_pkts, traffic_tolerance)
                if stats:
                    log.info("traffic is passed after removing the ACL")
                else:
                    log.error("Traffic failed with ACL is removed")
                    self.failed(goto=['cleanup'])
            try:
                for id in stream_ids[handle_tx]:
                    result = spirent.sth.traffic_config(port_handle=handle_tx, mode='reset', stream_id=id)
                    log.info('result %s' % result)
                    log.info('Traffic removed')
            except Exception as e:
                log.error('Failed to remove the traffic streams: %e ' % e)
                self.failed(goto=['cleanup'])
    @aetest.test
    def tc_check_trace_crash(self):
        failure = 0
        # need some clarification
        uut = self.script_args['uut']
        log.info("Verification of show logging and show context location all")
        try:
            res = verify_show_logging_context(uut)
            if not res:
                log.error('Crash Check Failed')
                self.failed()
        except Exception as e:
            log.error(
                'Verification of show logging and show context location all failed in the router %s as %s' % (uut, e))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        uut = self.script_args['uut']
        try:
            log.info("Reset the port configuration to default")
            log.info("removing ACL  configuration")
            conf = self.script_args['unconfig']
            uut.config(conf)
        except Exception as e:
            log.error('Test Clean up is failed: %s ' % e)
            self.failed()

class L2acl_triggers_tc(aetest.Testcase):
    global direction
    for direction in ['ingress']:
        @aetest.loop(ids=['triggers'])
        @aetest.test
        def tc_setup(self):
            intf_mode = self.script_args['intf_mode']
            acl_name = 'triggers'
            self.script_args['acl_name'] = acl_name
            acl_trigger= esacl_triggers_tc_dic()
            port_data = self.script_args['port_data']
            uut_name = self.script_args['uut_name']
            LOC = self.script_args['LOC']
            #ForkedPdb().set_trace()
            uut = self.script_args['uut']
            #pdb.set_trace()
            self.script_args['unconfig'] = ""
            extra_args = dict()
            interface = port_data[uut_name]['neighbors']['TGN-SPIRENT'][1]['interface']['name']
            traffic_tolerance = 0.2
            stream_ids = dict()
            if intf_mode == "subinterface":
                encap = acl_trigger[acl_name]['encap']
                for id in port_data[uut_name]['neighbors']['TGN-SPIRENT'].keys():
                    intf = port_data[uut_name]['neighbors']['TGN-SPIRENT'][id]['interface']['name']
                    conf_double = """
                    interface %s l2transport
                    %s
                    """ %(intf+".100",encap)
                    try:
                        uut.config(conf_double)
                    except Exception as e:
                        log.error('Failed to configure double tag encapsultion %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                        self.failed(goto=['cleanup'])
                    try:
                        log.info("Checking the encapsulation")
                        uut.execute("show running-config interface %s" % (intf+".100"))
                    except Exception as e:
                        log.error('Failed to double tag encapsultion  on interface %s  : %s ' % (interface + ".100", e))
                        self.failed(goto=['cleanup'])
            (xcon_res, xcon_msg) = check_xc_state(uut, "XCON")
            if xcon_res:
                log.info("XCONECT is UP")
                log.info(xcon_msg)
            else:
                log.error("XCONEECT is not up %s" % xcon_msg)
                self.failed(goto=['cleanup'])
            log.info("Clear interface counters before running traffic")
            try:
                uut.execute("clear counters")
            except Exception as e:
                log.error('Failed to clear interface counters : %s ' % e)
                self.failed()
            tgen = self.script_args['tgen_ip_var']
            failure_hex = 0
            if (direction == 'ingress'):
                handle_tx = self.script_args['tgen_hdls'][0]
                handle_rx = self.script_args['tgen_hdls'][1]
            else:
                handle_tx = self.script_args['tgen_hdls'][1]
                handle_rx = self.script_args['tgen_hdls'][0]
            strem_details = dict()
            stream_ids[handle_tx] = []
            tgen_pkt_rate = 10000
            #ForkedPdb().set_trace()
            handle = [handle_tx,handle_rx]
            streams = list(acl_trigger[acl_name]['stream'].keys())
            for i in streams :
                i = int(i)
                params = list(acl_trigger[acl_name]['stream'][i]['params'].keys())
                if 'mac_src' not in params:
                    acl_trigger[acl_name]['stream'][i]['params']['mac_src'] = 'aa:bb:cc:dd:ee:ff'
                if 'mac_dst' not in params:
                    acl_trigger[acl_name]['stream'][i]['params']['mac_dst'] = 'ff:ee:dd:cc:bb:aa'
                if 'l3_protocol' not in params:
                    acl_trigger[acl_name]['stream'][i]['params']['l3_protocol'] = 'ipv4'
                if 'vlan_id' not in params:
                    acl_trigger[acl_name]['stream'][i]['params']['vlan_id'] = '100'
                extra_args = acl_trigger[acl_name]['stream'][i]['params']
                #ForkedPdb().set_trace()
                try:
                    trafficList = spirent.sth.traffic_config(inter_stream_gap_unit='bytes',
                                                             #mac_src_step=1,
                                                             ip_src_mode='fixed',
                                                             l2_encap='ethernet_ii_vlan',
                                                             mac_src_mode='fixed',
                                                             length_mode='fixed',
                                                             #mac_dst_step=1,
                                                             rate_pps=tgen_pkt_rate,
                                                             ip_dst_mode='fixed',
                                                             mac_dst_mode='fixed',
                                                             #l3_protocol='ipv4',
                                                             #mac_dst=acl_edits[acl_name]['stream'][i]['params']['mac_dst'],
                                                             enable_stream_only_gen=0,
                                                             ip_ttl=64,
                                                             inter_stream_gap='116.0',
                                                             mode='create',
                                                             frame_size=pkt_size,
                                                             transmit_mode='continuous',
                                                             pkts_per_burst=pkts_per_burst,
                                                             #mac_src=streams[i]['params']['mac_src'],
                                                             #vlan_id=streams[i]['params']['vlan_id'],
                                                             #vlan_user_priority = streams[i]['params']['vlan_user_priority'],
                                                             # vlan_tpid:'33024',
                                                             port_handle=handle_tx,
                                                             # port_handle=handle,
                                                             enable_stream=0,
                                                             **extra_args
                                                             )
                    stream_ids[handle_tx].append(trafficList['stream_id'])
                    self.script_args['stream_ids'] = stream_ids
                    #ForkedPdb().set_trace()
                except Exception as e:
                    log.error(' sth.traffic_config for %s Failed trafficconfig_result:%s error: %s' %
                              (tgen, str(trafficList), e))
                    log.error('sth.traffic_config for Failed trafficconfig_result: %s ' % e)
                    self.failed(goto=['cleanup'])
            LOC = self.script_args['LOC']
            #ForkedPdb().set_trace()
            for acl_id in acl_trigger[acl_name]['acl'].keys():
                j = 1
                acl_list = acl_trigger[acl_name]['acl'][acl_id]['ace_list']
                conf = '''ethernet-services access-list %s
                 %s ''' %(acl_name, acl_list)
                try:
                    uut.config(conf)
                except Exception as e:
                    log.error("Cant load config, failed as %s" % e)
                if intf_mode == 'interface':
                    try:
                        conf_str = '''
                        interface %s
                        ethernet-services access-group %s %s
                        ''' % (interface, acl_name,direction)
                        uut.config(conf_str)
                        noconfig = """
                        interface %s
                        no ethernet-services access-group %s %s
                        root
                        no ethernet-services access-list %s
                        """ % (interface, acl_name,direction,acl_name)
                        self.script_args['unconfig'] +=noconfig
                    except Exception as e:
                        log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface, acl_name,e))
                        self.failed(goto=['cleanup'])
                elif intf_mode == 'subinterface':
                    try:
                        conf_str = '''
                        interface %s l2transport
                        ethernet-services access-group %s %s '''% (interface + ".100", acl_name,direction)
                        noconfig = """
                            interface %s l2transport
                            no ethernet-services access-group %s %s
                            root
                            no ethernet-services access-list %s
                            """ % (interface + ".100", acl_name, direction, acl_name)
                        self.script_args['unconfig'] += noconfig
                        uut.config(conf_str)
                    except Exception as e:
                        log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                        self.failed(goto=['cleanup'])
                for loc in LOC:
                    log.info("Clearing  ES ACL Counters counters before running traffic")
                    clera_acl = ("clear access-list ethernet-services %s hardware %s location %s" % (acl_name, direction, loc+"/CPU0"))
                    try:
                        uut.execute(clera_acl)
                    except Exception as e:
                        log.error('Failed to clear ES ACL Counters : %s ' % e)
                        self.failed(goto=['cleanup'])
                seq_list = dict()
                seq_list['seq'] = dict()

                keylist = list(acl_trigger[acl_name]['acl'][acl_id]['stream'].keys())
                for i in keylist:
                    #i = str(i)
                    if i == 'params':
                        continue
                    seq = acl_trigger[acl_name]['acl'][acl_id]['stream'][i]['seq']  # 10 20 30 40 implicit
                    seq_list['seq'][i] = seq  # 10 20 30 40 implicit i = 1,2,3,4
                log.info("starting the traffic")
                log.info("Clear interface counters before running traffic")
                try:
                    uut.execute("clear counters")
                except Exception as e:
                    log.error('Failed to clear interface counters : %s ' % e)
                    self.failed(goto=['cleanup'])
                log.info("Clear stats before starting the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                    log.info('Traffic clear status : %s' % result['status'])
                except Exception as e:
                    log.error('Failed to clear port counters: %s ' % e)
                    self.failed(goto=['cleanup'])

                # with self.steps.start("Start the capture to get the capure packets") as step:
                log.info("Starting the traffic for 7secs")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
                except Exception as e:
                    log.error('Failed to start traffic: ' % e)
                    failure_hex += 1
                    # self.failed()
                    time.sleep(7)
                log.info("stoping the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                    log.info("Poling: STC to see if traffic has stopped")
                except Exception as e:
                    log.error('Failed to stop the  traffic: ' % e)
                log.info("cheching the traffic stats and verifying the TX and RX packets")
                try:
                    stats_list = spirent.sth.traffic_stats(port_handle = handle_tx, mode='streams',
                                                           rx_port_handle='all', )
                except Exception as e:
                    log.error('Failed collect the stats and hence verification got failed for the traffic : %s' % e)
                    self.failed(goto=['cleanup'])
                    failure_hex += 1
                    # Get the TGN TX RX pkt count
                for stream in stream_ids[handle_tx]:
                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                        rx_pkts = 0
                    else:
                        rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                        tx_pkts = 0
                    else:
                        tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                    rx_pkts = int(rx_pkts)
                    tx_pkts = int(tx_pkts)
                    #ForkedPdb().set_trace()
                    #ForkedPdb().set_trace()
                    if tx_pkts == 0:
                        log.info("Tx Packets are 0")
                        self.failed(goto=['cleanup'])
                    seq = str(seq_list['seq'][j])
                    j = j+1
                    stats = verify_stats(uut, tx_pkts, rx_pkts, seq, acl_name, direction, loc, traffic_tolerance,
                                         stream)
                    if stats:
                        log.info("traffic and ACL deny and permit is working fine with %s ACL with seq %s" % (
                        acl_name, seq))
                    else:
                        log.error("traffic and ACL deny and permit is not working fine with %s ACL with seq %s" % (
                        acl_name, seq))
                        self.failed(goto=['cleanup'])
        @aetest.test
        def tc_interface_shut_trigger(self):
            failure = 0
            # need some clarification
            rtr_name = self.script_args['uut_name']
            port_handles = self.script_args['tgen_hdls']
            interface = self.script_args['port_data']
            acl_trigger = esacl_triggers_tc_dic()
            loc = self.script_args['LOC']
            #pdb.set_trace()
            uut = self.script_args['uut']
            acl_id = 1
            traffic_tolerance = 0.2
            acl_name = self.script_args['acl_name']
            uut_name = self.script_args['uut_name']
            neighbor = interface[uut_name]['neighbors']['TGN-SPIRENT']
            stream_ids = dict()
            stream_ids = self.script_args['stream_ids']
            seq_list = dict()
            seq_list['seq'] = dict()
            keylist = list(acl_trigger[acl_name]['acl'][acl_id]['stream'].keys())
            for i in keylist:
                if i == 'params':
                    continue
                seq = acl_trigger[acl_name]['acl'][acl_id]['stream'][i]['seq']  # 10 20 30 40 implicit
                seq_list['seq'][i] = seq  # 10 20 30 40 implicit i = 1,2,3,4
            j = 1
            for indx in neighbor.keys():
                intf = interface[uut_name]['neighbors']['TGN-SPIRENT'][indx]['interface']['name']
                conf = '''
                        interface %s
                            shutdow
                        ''' % (intf)
                uut.config(conf)
            for indx in neighbor.keys():
                intf = interface[uut_name]['neighbors']['TGN-SPIRENT'][indx]['interface']['name']
                conf = '''
                        interface %s
                          no  shutdow
                        ''' % (intf)
                uut.config(conf)
            time.sleep(20)
            (xcon_res, xcon_msg) = check_xc_state(uut, "XCON")
            if xcon_res:
                log.info("XCONECT is UP")
                log.info(xcon_msg)
            else:
                log.error("XCONEECT is not up after 20 sec after no shut on the interfaces %s" % xcon_msg)
                self.failed(goto=['cleanup'])
            log.info("Clear interface counters before running traffic")
            failure_hex = 0
            #pdb.set_trace()
            if (direction == 'ingress'):
                handle_tx = self.script_args['tgen_hdls'][0]
                handle_rx = self.script_args['tgen_hdls'][1]
            else:
                handle_tx = self.script_args['tgen_hdls'][1]
                handle_rx = self.script_args['tgen_hdls'][0]
            strem_details = dict()
            tgen_pkt_rate = 10000
            handle = [handle_tx, handle_rx]
            log.info("starting the traffic")
            log.info("Clear interface counters before running traffic")
            try:
                uut.execute("clear counters")
            except Exception as e:
                log.error('Failed to clear interface counters : %s ' % e)
                self.failed(goto=['cleanup'])
            log.info("Clear stats before starting the traffic")
            for lc in loc:
                log.info("Clearing  ES ACL Counters counters before running traffic")
                clera_acl = (
                "clear access-list ethernet-services %s hardware %s location %s" % (acl_name, direction, lc + "/CPU0"))
                try:
                    uut.execute(clera_acl)
                except Exception as e:
                    log.error('Failed to clear ES ACL Counters : %s ' % e)
                    self.failed(goto=['cleanup'])
            try:
                result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                log.info('Traffic clear status : %s' % result['status'])
            except Exception as e:
                log.error('Failed to clear port counters: %s ' % e)
                self.failed(goto=['cleanup'])
            log.info("Starting the traffic for 7secs")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
            except Exception as e:
                log.error('Failed to start traffic: ' % e)
                failure_hex += 1
                # self.failed()
                time.sleep(7)
            log.info("stoping the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                log.info("Poling: STC to see if traffic has stopped")
            except Exception as e:
                log.error('Failed to stop the  traffic: ' % e)
            log.info("cheching the traffic stats and verifying the TX and RX packets")
            #pdb.set_trace()
            try:
                stats_list = spirent.sth.traffic_stats(port_handle=handle_tx, mode='streams',
                                                       rx_port_handle='all', )
            except Exception as e:
                log.error('Failed collect the stats and hence verification got failed for the traffic: %s ' % e)
                failure_hex += 1
                # Get the TGN TX RX pkt count
            for stream in stream_ids[handle_tx]:
                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                    rx_pkts = 0
                else:
                    rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                    tx_pkts = 0
                else:
                    tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                rx_pkts = int(rx_pkts)
                tx_pkts = int(tx_pkts)
                if tx_pkts == 0:
                    log.info("Tx Packets are 0")
                    self.failed(goto=['cleanup'])
                seq = str(seq_list['seq'][j])
                j = j + 1
                stats = verify_stats(uut, tx_pkts, rx_pkts, seq, acl_name, direction, lc, traffic_tolerance,
                                     stream)
                if stats:
                    log.info(
                        "traffic and ACL deny and permit is working fine with %s ACL with seq %s" % (acl_name, seq))
                else:
                    log.error(
                        "traffic and ACL deny and permit is not working fine with %s ACLwith seq %s" % (acl_name, seq))
                    self.failed(goto=['cleanup'])

        @aetest.test
        def tc_hw_module_reload_trigger(self):
            port_handles = self.script_args['tgen_hdls']
            interface = self.script_args['port_data']
            process_name = 'vlan_ma'
            uut = self.script_args['uut']
            acl_trigger = esacl_triggers_tc_dic()
            loc = self.script_args['LOC']
            uut = self.script_args['uut']
            acl_id = 1
            traffic_tolerance = 0.2
            acl_name = self.script_args['acl_name']
            uut_name = self.script_args['uut_name']
            neighbor = interface[uut_name]['neighbors']['TGN-SPIRENT']
            seq_list = dict()
            seq_list['seq'] = dict()
            keylist = list(acl_trigger[acl_name]['acl'][acl_id]['stream'].keys())
            for i in keylist:
                # i = str(i)
                if i == 'params':
                    continue
                seq = acl_trigger[acl_name]['acl'][acl_id]['stream'][i]['seq']  # 10 20 30 40 implicit
                seq_list['seq'][i] = seq  # 10 20 30 40 implicit i = 1,2,3,4
            x = 1
            stream_ids = dict()
            stream_ids = self.script_args['stream_ids']
            retList = dict()
            retList['port'] = dict()
            retList['status'] = ""
            is_eXR = 1
            for lc in loc:
                loc = str(lc)
                res = admin_lc_reload(uut, loc)
                if not res:
                    log.error("HW LC reload is failed")
                    self.failed(goto=['cleanup'])
            #time.sleep(20)
            for indx in neighbor.keys():
                intf = interface[uut_name]['neighbors']['TGN-SPIRENT'][indx]['interface']['name']
                cmd = "show interfaces %s" % (intf)
                sucess = False
                for j in range(1, 5):
                    time.sleep(2)
                    result = uut.execute(cmd)
                    if (re.search(r'line\s+protocol\s+is\s+up', result)):
                        sucess = True
                        break
                if not sucess:
                    log.info("interfaces %s , in not up" % (intf))
                    self.failed(goto=['cleanup'])
            (xcon_res, xcon_msg) = check_xc_state(uut, "XCON")
            if xcon_res:
                log.info("XCONECT is UP")
                log.info(xcon_msg)
            else:
                log.error("XCONEECT is not up after 20 sec after no shut on the interfaces %s" % xcon_msg)
                self.failed(goto=['cleanup'])
            log.info("Clear interface counters before running traffic")
            failure_hex = 0
            #pdb.set_trace()
            if (direction == 'ingress'):
                handle_tx = self.script_args['tgen_hdls'][0]
                handle_rx = self.script_args['tgen_hdls'][1]
            else:
                handle_tx = self.script_args['tgen_hdls'][1]
                handle_rx = self.script_args['tgen_hdls'][0]
            strem_details = dict()
            tgen_pkt_rate = 10000
            # ForkedPdb().set_trace()
            handle = [handle_tx, handle_rx]
            log.info("starting the traffic")
            log.info("Clear interface counters before running traffic")
            try:
                uut.execute("clear counters")
            except Exception as e:
                log.error('Failed to clear interface counters : %s ' % e)
                self.failed(goto=['cleanup'])
            log.info("Clear stats before starting the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                log.info('Traffic clear status : %s' % result['status'])
            except Exception as e:
                log.error('Failed to clear port counters: %s ' % e)
                self.failed(goto=['cleanup'])

            # with steps.start("Start the capture to get the capure packets") as step:
            log.info("Starting the traffic for 7secs")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
            except Exception as e:
                log.error('Failed to start traffic: ' % e)
                failure_hex += 1
                # self.failed()
                time.sleep(7)
            log.info("stoping the traffic")
            try:
                result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                log.info("Poling: STC to see if traffic has stopped")
            except Exception as e:
                log.error('Failed to stop the  traffic: ' % e)
            log.info("cheching the traffic stats and verifying the TX and RX packets")
            try:
                stats_list = spirent.sth.traffic_stats(port_handle=handle_tx, mode='streams',
                                                       rx_port_handle='all', )
            except Exception as e:
                log.error('Failed collect the stats and hence verification got failed for the traffic:: %s ' % e)
                failure_hex += 1
            # Get the TGN TX RX pkt count
            pdb.set_trace()
            for stream in stream_ids[handle_tx]:
                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                    rx_pkts = 0
                else:
                    rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                    tx_pkts = 0
                else:
                    tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                rx_pkts = int(rx_pkts)
                tx_pkts = int(tx_pkts)
                # ForkedPdb().set_trace()
                # ForkedPdb().set_trace()
                if tx_pkts == 0:
                    log.info("Tx Packets are 0")
                    self.failed(goto=['cleanup'])
                seq = str(seq_list['seq'][x])
                x = x + 1
                stats = verify_stats(uut, tx_pkts, rx_pkts, seq, acl_name, direction, lc, traffic_tolerance,
                                     stream)
                if stats:
                    log.info(
                        "traffic and ACL deny and permit is working fine with %s ACL with seq %s" % (acl_name, seq))
                else:
                    log.error("traffic and ACL deny and permit is not working fine with %s ACL with seq %s" % (
                        acl_name, seq))
                    self.failed(goto=['cleanup'])
        @aetest.test
        def tc_check_trace_crash(self):
            failure = 0
            # need some clarification
            uut = self.script_args['uut']
            log.info("Verification of show logging and show context location all")
            try:
                res = verify_show_logging_context(uut)
                if not res:
                    log.error('Crash Check Failed')
                    self.failed()
            except Exception as e:
                log.error(
                    'Verification of show logging and show context location all failed in the router %s as %s' % (uut, e))
                self.failed()

        @aetest.cleanup
        def cleanup(self):
            uut = self.script_args['uut']
            try:
                log.info("Reset the port configuration to default")
                log.info("removing ACL  configuration")
                conf = self.script_args['unconfig']
                uut.config(conf)
            except Exception as e:
                log.error('Test Clean up is failed: %s ' % e)
                self.failed()

class L2aclPositive_acl_double_tag(aetest.Testcase):
    @aetest.loop(ids = ['dot1q_dot1q','dot1ad_dot1q'])
    @aetest.test
    def tc_setup(self):
        intf_mode = self.script_args['intf_mode']
        acl_name = self.section.id
        acl_double = acl_double_tag_dic()
        port_data = self.script_args['port_data']
        #ForkedPdb().set_trace()
        uut = self.script_args['uut']
        self.script_args['unconfig'] = ""
        extra_args = dict()
        uut_name = self.script_args['uut_name']
        interface = port_data[uut_name]['neighbors']['TGN-SPIRENT'][1]['interface']['name']
        traffic_tolerance = 0.2
        stream_ids = dict()
        if intf_mode == "subinterface":
            encap = acl_double[acl_name]['encap']
            for id in port_data[uut_name]['neighbors']['TGN-SPIRENT'].keys():
                intf = port_data[uut_name]['neighbors']['TGN-SPIRENT'][id]['interface']['name']
                conf_double = """
                interface %s l2transport
                %s
                """ %(intf+".100",encap)
                try:
                    uut.config(conf_double)
                except Exception as e:
                    log.error('Failed to configure double tag encapsultion %s on interface %s  : %s ' % (intf + ".100", acl_name, e))
                    self.failed(goto=['cleanup'])
                try:
                    log.info("Checking the encapsulation")
                    uut.execute("show running-config interface %s" % (intf+".100"))
                except Exception as e:
                    log.error('Failed to double tag encapsultion  on interface %s  : %s ' % (intf + ".100", e))
                    self.failed(goto=['cleanup'])
        (xcon_res, xcon_msg) = check_xc_state(uut, "XCON")
        if xcon_res:
            log.info("XCONECT is UP")
            log.info(xcon_msg)
        else:
            log.error("XCONEECT is not up %s" % xcon_msg)
            self.failed(goto=['cleanup'])
        log.info("Clear interface counters before running traffic")
        try:
            uut.execute("clear counters")
        except Exception as e:
            log.error('Failed to clear interface counters : %s ' % e)
            self.failed()
        tgen = self.script_args['tgen_ip_var']
        for direction in ['ingress']:
            failure_hex = 0
            if (direction == 'ingress'):
                handle_tx = self.script_args['tgen_hdls'][0]
                handle_rx = self.script_args['tgen_hdls'][1]
            else:
                handle_tx = self.script_args['tgen_hdls'][1]
                handle_rx = self.script_args['tgen_hdls'][0]
            strem_details = dict()
            stream_ids[handle_tx] = []
            tgen_pkt_rate = 10000
            #ForkedPdb().set_trace()
            handle = [handle_tx,handle_rx]
            streams = list(acl_double[acl_name]['stream'].keys())
            for i in streams :
                i = int(i)
                params = list(acl_double[acl_name]['stream'][i]['params'].keys())
                if 'mac_src' not in params:
                    acl_double[acl_name]['stream'][i]['params']['mac_src'] = 'aa:bb:cc:dd:ee:ff'
                if 'mac_dst' not in params:
                    acl_double[acl_name]['stream'][i]['params']['mac_dst'] = 'ff:ee:dd:cc:bb:aa'
                if 'l3_protocol' not in params:
                    acl_double[acl_name]['stream'][i]['params']['l3_protocol'] = 'ipv4'
                if 'vlan_id' not in params:
                    acl_double[acl_name]['stream'][i]['params']['vlan_id'] = '100'
                extra_args = acl_double[acl_name]['stream'][i]['params']
                #ForkedPdb().set_trace()
                try:
                    trafficList = spirent.sth.traffic_config(inter_stream_gap_unit='bytes',
                                                             #mac_src_step=1,
                                                             ip_src_mode='fixed',
                                                             l2_encap='ethernet_ii_vlan',
                                                             mac_src_mode='fixed',
                                                             length_mode='fixed',
                                                             #mac_dst_step=1,
                                                             rate_pps=tgen_pkt_rate,
                                                             ip_dst_mode='fixed',
                                                             mac_dst_mode='fixed',
                                                             #l3_protocol='ipv4',
                                                             #mac_dst=acl_edits[acl_name]['stream'][i]['params']['mac_dst'],
                                                             enable_stream_only_gen=0,
                                                             ip_ttl=64,
                                                             inter_stream_gap='116.0',
                                                             mode='create',
                                                             frame_size=pkt_size,
                                                             transmit_mode='continuous',
                                                             pkts_per_burst=pkts_per_burst,
                                                             #mac_src=streams[i]['params']['mac_src'],
                                                             #vlan_id=streams[i]['params']['vlan_id'],
                                                             #vlan_user_priority = streams[i]['params']['vlan_user_priority'],
                                                             # vlan_tpid:'33024',
                                                             port_handle=handle_tx,
                                                             # port_handle=handle,
                                                             enable_stream=0,
                                                             **extra_args
                                                             )
                    stream_ids[handle_tx].append(trafficList['stream_id'])
                    self.script_args['stream_ids'] = stream_ids
                    #ForkedPdb().set_trace()
                except Exception as e:
                    log.error(' sth.traffic_config for %s Failed trafficconfig_result:%s error: %s' %
                              (tgen, str(trafficList), e))
                    log.error('sth.traffic_config for Failed trafficconfig_result: %s ' % e)
                    self.failed(goto=['cleanup'])
            LOC = self.script_args['LOC']
            #ForkedPdb().set_trace()
            for acl_id in acl_double[acl_name]['acl'].keys():
                j = 1
                acl_list = acl_double[acl_name]['acl'][acl_id]['ace_list']
                conf = '''ethernet-services access-list %s
                 %s ''' %(acl_name, acl_list)
                try:
                    uut.config(conf)
                except Exception as e:
                    log.error("Cant load config, failed as %s" % e)
                if intf_mode == 'interface':
                    try:
                        conf_str = '''
                        interface %s
                        ethernet-services access-group %s %s
                        ''' % (interface, acl_name,direction)
                        uut.config(conf_str)
                        noconfig = """
                        interface %s
                        no ethernet-services access-group %s %s
                        root
                        no ethernet-services access-list %s
                        """ % (interface, acl_name,direction,acl_name)
                        self.script_args['unconfig'] +=noconfig
                    except Exception as e:
                        log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface, acl_name,e))
                        self.failed(goto=['cleanup'])
                elif intf_mode == 'subinterface':
                    try:
                        conf_str = '''
                        interface %s l2transport
                        ethernet-services access-group %s %s '''% (interface + ".100", acl_name,direction)
                        noconfig = """
                            interface %s l2transport
                            no ethernet-services access-group %s %s
                            root
                            no ethernet-services access-list %s
                            """ % (interface + ".100", acl_name, direction, acl_name)
                        self.script_args['unconfig'] += noconfig
                        uut.config(conf_str)
                    except Exception as e:
                        log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                        self.failed(goto=['cleanup'])
                for loc in LOC:
                    log.info("Clearing  ES ACL Counters counters before running traffic")
                    clera_acl = ("clear access-list ethernet-services %s hardware %s location %s" % (acl_name, direction, loc+"/CPU0"))
                    try:
                        uut.execute(clera_acl)
                    except Exception as e:
                        log.error('Failed to clear ES ACL Counters : %s ' % e)
                        self.failed(goto=['cleanup'])
                seq_list = dict()
                seq_list['seq'] = dict()

                keylist = list(acl_double[acl_name]['acl'][acl_id]['stream'].keys())
                for i in keylist:
                    #i = str(i)
                    if i == 'params':
                        continue
                    seq = acl_double[acl_name]['acl'][acl_id]['stream'][i]['seq']  # 10 20 30 40 implicit
                    seq_list['seq'][i] = seq  # 10 20 30 40 implicit i = 1,2,3,4
                log.info("starting the traffic")
                log.info("Clear interface counters before running traffic")
                try:
                    uut.execute("clear counters")
                except Exception as e:
                    log.error('Failed to clear interface counters : %s ' % e)
                    self.failed(goto=['cleanup'])
                log.info("Clear stats before starting the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                    log.info('Traffic clear status : %s' % result['status'])
                except Exception as e:
                    log.error('Failed to clear port counters: %s ' % e)
                    self.failed(goto=['cleanup'])

                # with self.steps.start("Start the capture to get the capure packets") as step:
                log.info("Starting the traffic for 7secs")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
                except Exception as e:
                    log.error('Failed to start traffic: ' % e)
                    failure_hex += 1
                    # self.failed()
                    time.sleep(7)
                log.info("stoping the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                    log.info("Poling: STC to see if traffic has stopped")
                except Exception as e:
                    log.error('Failed to stop the  traffic: ' % e)
                log.info("cheching the traffic stats and verifying the TX and RX packets")
                try:
                    stats_list = spirent.sth.traffic_stats(port_handle = handle_tx, mode='streams',
                                                           rx_port_handle='all', )
                except Exception as e:
                    log.error('Failed collect the stats and hence verification got failed for the traffic:: %s ' % e)
                    self.failed(goto=['cleanup'])
                    failure_hex += 1
                    # Get the TGN TX RX pkt count
                for stream in stream_ids[handle_tx]:
                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                        rx_pkts = 0
                    else:
                        rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                        tx_pkts = 0
                    else:
                        tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                    rx_pkts = int(rx_pkts)
                    tx_pkts = int(tx_pkts)
                    if tx_pkts == 0:
                        log.info("Tx Packets are 0")
                        self.failed(goto=['cleanup'])
                    seq = str(seq_list['seq'][j])
                    j = j + 1
                    stats = verify_stats(uut,tx_pkts,rx_pkts,seq,acl_name,direction,loc,traffic_tolerance,stream)
                    if stats:
                        log.info("traffic and ACL deny and permit is working fine with %s ACL with seq %s" % (
                        acl_name, seq))
                    else:
                        log.error("traffic and ACL deny and permit is not working fine with %s ACL with seq %s" % (
                        acl_name, seq))
                        self.failed(goto=['cleanup'])

                log.info("Removing the ACL and Checking the traffic")
                if intf_mode == 'interface':
                    try:
                        conf_str = '''
                        interface %s
                        no ethernet-services access-group %s %s
                        root
                        no ethernet-services access-list %s
                        ''' % (interface, acl_name, direction, acl_name)
                        uut.config(conf_str)
                    except Exception as e:
                        log.error('Failed to remove ES ACL %s on interface %s  : %s ' % (interface, acl_name, e))
                        self.failed(goto=['cleanup'])
                elif intf_mode == 'subinterface':
                    try:
                        conf_str = '''
                        interface %s
                        no ethernet-services access-group %s %s
                        root
                        no ethernet-services access-list %s ''' % (interface + ".100", acl_name, direction, acl_name)
                        uut.config(conf_str)
                    except Exception as e:
                        log.error('Failed to remove ES ACL %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                        self.failed(goto=['cleanup'])
                log.info("starting the traffic")
                # ForkedPdb().set_trace()
                # with self.steps.start("Clear stats before starting the traffic") as step:
                log.info("Clear stats before starting the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                    log.info('Traffic clear status : %s' % result['status'])
                except Exception as e:
                    log.error('Failed to clear port counters: %s ' % e)
                    self.failed(goto=['cleanup'])
                log.info("Starting the traffic for 7secs")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
                except Exception as e:
                    log.error('Failed to start traffic: ' % e)
                    self.failed(goto=['cleanup'])
                time.sleep(7)
                log.info("stoping the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                    log.info("Poling: STC to see if traffic has stopped")
                except Exception as e:
                    log.error('Failed to stop the  traffic: ' % e)
                    self.failed(goto=['cleanup'])
                log.info("cheching the traffic stats and verifying the TX and RX packets")
                try:
                    stats_list = spirent.sth.traffic_stats(port_handle=handle_tx, mode='streams',
                                                           rx_port_handle='all', )
                except Exception as e:
                    log.error('Failed collect the stats and hence verification got failed for the traffic:: %s ' % e)
                    self.failed(goto=['cleanup'])
                for stream in stream_ids[handle_tx]:
                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                        rx_pkts = 0
                    else:
                        rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                        tx_pkts = 0
                    else:
                        tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                    rx_pkts = int(rx_pkts)
                    tx_pkts = int(tx_pkts)
                    stats = verify_stats_without_acl(rx_pkts,tx_pkts,traffic_tolerance)
                    if stats :
                        log.info("traffic is passed after removing the ACL")
                    else :
                        log.error("Traffic failed with ACL is removed")
                        self.failed(goto=['cleanup'])
                try:
                    for id in stream_ids[handle_tx]:
                        result = spirent.sth.traffic_config(port_handle=handle_tx, mode='reset', stream_id=id)
                        log.info('result %s' % result)
                        log.info('Traffic removed')
                except Exception as e:
                    log.error('Failed to remove the traffic streams: %e ' % e)
                    self.failed(goto=['cleanup'])

    @aetest.test
    def tc_check_trace_crash(self):
        failure = 0
        # need some clarification
        uut = self.script_args['uut']
        log.info("Verification of show logging and show context location all")
        try:
            res = verify_show_logging_context(uut)
            if not res:
                log.error('Crash Check Failed')
                self.failed()
        except Exception as e:
            log.error(
                'Verification of show logging and show context location all failed in the router %s as %s' % (uut, e))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        uut = self.script_args['uut']
        try:
            log.info("Reset the port configuration to default")
            log.info("removing ACL  configuration")
            conf = self.script_args['unconfig']
            uut.config(conf)
        except Exception as e:
            log.error('Test Clean up is failed: %s ' % e)
            self.failed()

class L2aclPositive_with_rewrite_tag(aetest.Testcase):
    @aetest.loop(ids = ['translate_1_to_2','pop_1'])
    @aetest.test
    def tc_setup(self):
        intf_mode = self.script_args['intf_mode']
        acl_name = self.section.id
        acl_with_rewrite = acl_with_rewrite_dic()
        port_data = self.script_args['port_data']
        #ForkedPdb().set_trace()
        uut = self.script_args['uut']
        self.script_args['unconfig'] = ""
        extra_args = dict()
        uut_name = self.script_args['uut_name']
        interface = port_data[uut_name]['neighbors']['TGN-SPIRENT'][1]['interface']['name']
        traffic_tolerance = 0.2
        stream_ids = dict()
        tgen = self.script_args['tgen_ip_var']
        #this code should fine for both Egress and ingress , if we want to add vlan to ACL we need modify the code do check the direction
        #and ACL should  be changed since vlans get change due to rewrite.
        for direction in ['ingress']:
            failure_hex = 0
            if (direction == 'ingress') :
                handle_tx = self.script_args['tgen_hdls'][0]
                handle_rx = self.script_args['tgen_hdls'][1]
                if intf_mode == "subinterface":
                    encap = acl_with_rewrite[acl_name]['encap_main']
                    intf = port_data[uut_name]['neighbors']['TGN-SPIRENT'][1]['interface']['name']
                    conf_double = """
                    interface %s l2transport
                    %s
                    """ % (intf + ".100", encap)
                    try:
                        uut.config(conf_double)
                    except Exception as e:
                        log.error('Failed to configure double tag encapsultion %s on interface %s  : %s ' % (
                        intf + ".100", acl_name, e))
                        self.failed(goto=['cleanup'])
                    try:
                        log.info("Checking the encapsulation")
                        uut.execute("show running-config interface %s" % (intf + ".100"))
                    except Exception as e:
                        log.error('Failed to double tag encapsultion  on interface %s  : %s ' % (intf + ".100", e))
                        self.failed(goto=['cleanup'])
                if intf_mode == "subinterface":
                    encap = acl_with_rewrite[acl_name]['encap']
                    intf = port_data[uut_name]['neighbors']['TGN-SPIRENT'][2]['interface']['name']
                    conf_double = """
                    interface %s l2transport
                    %s
                    """ % (intf + ".100", encap)
                    try:
                        uut.config(conf_double)
                    except Exception as e:
                        log.error('Failed to configure double tag encapsultion %s on interface %s  : %s ' % (
                        intf + ".100", acl_name, e))
                        self.failed(goto=['cleanup'])
                    try:
                        log.info("Checking the encapsulation")
                        uut.execute("show running-config interface %s" % (intf + ".100"))
                    except Exception as e:
                        log.error('Failed to double tag encapsultion  on interface %s  : %s ' % (intf + ".100", e))
                        self.failed(goto=['cleanup'])
            else :
                handle_tx = self.script_args['tgen_hdls'][1]
                handle_rx = self.script_args['tgen_hdls'][0]
                if intf_mode == "subinterface":
                    encap = acl_with_rewrite[acl_name]['encap_main']
                    intf = port_data[uut_name]['neighbors']['TGN-SPIRENT'][2]['interface']['name']
                    conf_double = """
                    interface %s l2transport
                    %s
                    """ % (intf + ".100", encap)
                    try:
                        uut.config(conf_double)
                    except Exception as e:
                        log.error('Failed to configure double tag encapsultion %s on interface %s  : %s ' % (
                        intf + ".100", acl_name, e))
                        self.failed(goto=['cleanup'])
                    try:
                        log.info("Checking the encapsulation")
                        uut.execute("show running-config interface %s" % (intf + ".100"))
                    except Exception as e:
                        log.error('Failed to double tag encapsultion  on interface %s  : %s ' % (intf + ".100", e))
                        self.failed(goto=['cleanup'])
                if intf_mode == "subinterface":
                    encap = acl_with_rewrite[acl_name]['encap']
                    intf = port_data[uut_name]['neighbors']['TGN-SPIRENT'][1]['interface']['name']
                    conf_double = """
                    interface %s l2transport
                    %s
                    """ % (intf + ".100", encap)
                    try:
                        uut.config(conf_double)
                    except Exception as e:
                        log.error('Failed to configure double tag encapsultion %s on interface %s  : %s ' % (
                        intf + ".100", acl_name, e))
                        self.failed(goto=['cleanup'])
                    try:
                        log.info("Checking the encapsulation")
                        uut.execute("show running-config interface %s" % (intf + ".100"))
                    except Exception as e:
                        log.error('Failed to double tag encapsultion  on interface %s  : %s ' % (intf + ".100", e))
                        self.failed(goto=['cleanup'])
            (xcon_res, xcon_msg) = check_xc_state(uut, "XCON")
            if xcon_res:
                log.info("XCONECT is UP")
                log.info(xcon_msg)
            else:
                log.error("XCONEECT is not up %s" % xcon_msg)
                self.failed(goto=['cleanup'])
            log.info("Clear interface counters before running traffic")
            try:
                uut.execute("clear counters")
            except Exception as e:
                log.error('Failed to clear interface counters : %s ' % e)
                self.failed()
            #if (direction == 'ingress'):
             #   handle_tx = self.script_args['tgen_hdls'][0]
              #  handle_rx = self.script_args['tgen_hdls'][1]
            #else:
             #   handle_tx = self.script_args['tgen_hdls'][1]
              #  handle_rx = self.script_args['tgen_hdls'][0]
            strem_details = dict()
            stream_ids[handle_tx] = []
            tgen_pkt_rate = 10000
            #ForkedPdb().set_trace()
            handle = [handle_tx,handle_rx]
            streams = list(acl_with_rewrite[acl_name]['stream'].keys())
            for i in streams :
                i = int(i)
                params = list(acl_with_rewrite[acl_name]['stream'][i]['params'].keys())
                if 'mac_src' not in params:
                    acl_with_rewrite[acl_name]['stream'][i]['params']['mac_src'] = 'aa:bb:cc:dd:ee:ff'
                if 'mac_dst' not in params:
                    acl_with_rewrite[acl_name]['stream'][i]['params']['mac_dst'] = 'ff:ee:dd:cc:bb:aa'
                if 'l3_protocol' not in params:
                    acl_with_rewrite[acl_name]['stream'][i]['params']['l3_protocol'] = 'ipv4'
                if 'vlan_id' not in params:
                    acl_with_rewrite[acl_name]['stream'][i]['params']['vlan_id'] = '100'
                extra_args = acl_with_rewrite[acl_name]['stream'][i]['params']
                #ForkedPdb().set_trace()
                try:
                    trafficList = spirent.sth.traffic_config(inter_stream_gap_unit='bytes',
                                                             #mac_src_step=1,
                                                             ip_src_mode='fixed',
                                                             l2_encap='ethernet_ii_vlan',
                                                             mac_src_mode='fixed',
                                                             length_mode='fixed',
                                                             #mac_dst_step=1,
                                                             rate_pps=tgen_pkt_rate,
                                                             ip_dst_mode='fixed',
                                                             mac_dst_mode='fixed',
                                                             #l3_protocol='ipv4',
                                                             #mac_dst=acl_edits[acl_name]['stream'][i]['params']['mac_dst'],
                                                             enable_stream_only_gen=0,
                                                             ip_ttl=64,
                                                             inter_stream_gap='116.0',
                                                             mode='create',
                                                             frame_size=pkt_size,
                                                             transmit_mode='continuous',
                                                             pkts_per_burst=pkts_per_burst,
                                                             #mac_src=streams[i]['params']['mac_src'],
                                                             #vlan_id=streams[i]['params']['vlan_id'],
                                                             #vlan_user_priority = streams[i]['params']['vlan_user_priority'],
                                                             # vlan_tpid:'33024',
                                                             port_handle=handle_tx,
                                                             # port_handle=handle,
                                                             enable_stream=0,
                                                             **extra_args
                                                             )
                    stream_ids[handle_tx].append(trafficList['stream_id'])
                    self.script_args['stream_ids'] = stream_ids
                    #ForkedPdb().set_trace()
                except Exception as e:
                    log.error(' sth.traffic_config for %s Failed trafficconfig_result:%s error: %s' %
                              (tgen, str(trafficList), e))
                    log.error('sth.traffic_config for Failed trafficconfig_result: %s ' % e)
                    self.failed(goto=['cleanup'])
            LOC = self.script_args['LOC']
            #ForkedPdb().set_trace()
            for acl_id in acl_with_rewrite[acl_name]['acl'].keys():
                j = 1
                acl_list = acl_with_rewrite[acl_name]['acl'][acl_id]['ace_list']
                conf = '''ethernet-services access-list %s
                 %s ''' %(acl_name, acl_list)
                try:
                    uut.config(conf)
                except Exception as e:
                    log.error("Cant load config, failed as %s" % e)
                if intf_mode == 'interface':
                    try:
                        conf_str = '''
                        interface %s
                        ethernet-services access-group %s %s
                        ''' % (interface, acl_name,direction)
                        uut.config(conf_str)
                        noconfig = """
                        interface %s
                        no ethernet-services access-group %s %s
                        root
                        no ethernet-services access-list %s
                        """ % (interface, acl_name,direction,acl_name)
                        self.script_args['unconfig'] +=noconfig
                    except Exception as e:
                        log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface, acl_name,e))
                        self.failed(goto=['cleanup'])
                elif intf_mode == 'subinterface':
                    try:
                        conf_str = '''
                        interface %s l2transport
                        ethernet-services access-group %s %s '''% (interface + ".100", acl_name,direction)
                        noconfig = """
                            interface %s l2transport
                            no ethernet-services access-group %s %s
                            root
                            no ethernet-services access-list %s
                            """ % (interface + ".100", acl_name, direction, acl_name)
                        self.script_args['unconfig'] += noconfig
                        uut.config(conf_str)
                    except Exception as e:
                        log.error('Failed to configure ES ACL %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                        self.failed(goto=['cleanup'])
                for loc in LOC:
                    log.info("Clearing  ES ACL Counters counters before running traffic")
                    clera_acl = ("clear access-list ethernet-services %s hardware %s location %s" % (acl_name, direction, loc+"/CPU0"))
                    try:
                        uut.execute(clera_acl)
                    except Exception as e:
                        log.error('Failed to clear ES ACL Counters : %s ' % e)
                        self.failed(goto=['cleanup'])
                seq_list = dict()
                seq_list['seq'] = dict()

                keylist = list(acl_with_rewrite[acl_name]['acl'][acl_id]['stream'].keys())
                for i in keylist:
                    #i = str(i)
                    if i == 'params':
                        continue
                    seq = acl_with_rewrite[acl_name]['acl'][acl_id]['stream'][i]['seq']  # 10 20 30 40 implicit
                    seq_list['seq'][i] = seq  # 10 20 30 40 implicit i = 1,2,3,4
                log.info("starting the traffic")
                log.info("Clear interface counters before running traffic")
                try:
                    uut.execute("clear counters")
                except Exception as e:
                    log.error('Failed to clear interface counters : %s ' % e)
                    self.failed(goto=['cleanup'])
                log.info("Clear stats before starting the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                    log.info('Traffic clear status : %s' % result['status'])
                except Exception as e:
                    log.error('Failed to clear port counters: %s ' % e)
                    self.failed(goto=['cleanup'])

                # with self.steps.start("Start the capture to get the capure packets") as step:
                log.info("Starting the traffic for 7secs")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
                except Exception as e:
                    log.error('Failed to start traffic: ' % e)
                    failure_hex += 1
                    # self.failed()
                    time.sleep(7)
                log.info("stoping the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                    log.info("Poling: STC to see if traffic has stopped")
                except Exception as e:
                    log.error('Failed to stop the  traffic: ' % e)
                log.info("cheching the traffic stats and verifying the TX and RX packets")
                try:
                    stats_list = spirent.sth.traffic_stats(port_handle = handle_tx, mode='streams',
                                                           rx_port_handle='all', )
                except Exception as e:
                    log.error('Failed collect the stats and hence verification got failed for the traffic:: %s ' % e)
                    self.failed(goto=['cleanup'])
                    failure_hex += 1
                    # Get the TGN TX RX pkt count
                for stream in stream_ids[handle_tx]:
                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                        rx_pkts = 0
                    else:
                        rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                        tx_pkts = 0
                    else:
                        tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                    rx_pkts = int(rx_pkts)
                    tx_pkts = int(tx_pkts)
                    if tx_pkts == 0:
                        log.info("Tx Packets are 0")
                        self.failed(goto=['cleanup'])
                    seq = str(seq_list['seq'][j])
                    j = j + 1
                    stats = verify_stats(uut,tx_pkts,rx_pkts,seq,acl_name,direction,loc,traffic_tolerance,stream)
                    if stats:
                        log.info("traffic and ACL deny and permit is working fine with %s ACL with seq %s" % (
                        acl_name, seq))
                    else:
                        log.error("traffic and ACL deny and permit is not working fine with %s ACL with seq %s" % (
                        acl_name, seq))
                        self.failed(goto=['cleanup'])

                log.info("Removing the ACL and Checking the traffic")
                if intf_mode == 'interface':
                    try:
                        conf_str = '''
                        interface %s
                        no ethernet-services access-group %s %s
                        root
                        no ethernet-services access-list %s
                        ''' % (interface, acl_name, direction, acl_name)
                        uut.config(conf_str)
                    except Exception as e:
                        log.error('Failed to remove ES ACL %s on interface %s  : %s ' % (interface, acl_name, e))
                        self.failed(goto=['cleanup'])
                elif intf_mode == 'subinterface':
                    try:
                        conf_str = '''
                        interface %s
                        no ethernet-services access-group %s %s
                        root
                        no ethernet-services access-list %s ''' % (interface + ".100", acl_name, direction, acl_name)
                        uut.config(conf_str)
                    except Exception as e:
                        log.error('Failed to remove ES ACL %s on interface %s  : %s ' % (interface + ".100", acl_name, e))
                        self.failed(goto=['cleanup'])
                log.info("starting the traffic")
                # ForkedPdb().set_trace()
                # with self.steps.start("Clear stats before starting the traffic") as step:
                log.info("Clear stats before starting the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle, action="clear_stats")
                    log.info('Traffic clear status : %s' % result['status'])
                except Exception as e:
                    log.error('Failed to clear port counters: %s ' % e)
                    self.failed(goto=['cleanup'])
                log.info("Starting the traffic for 7secs")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle_tx, action="run")
                except Exception as e:
                    log.error('Failed to start traffic: ' % e)
                    self.failed(goto=['cleanup'])
                time.sleep(7)
                log.info("stoping the traffic")
                try:
                    result = spirent.sth.traffic_control(port_handle=handle_tx, action='stop')
                    log.info("Poling: STC to see if traffic has stopped")
                except Exception as e:
                    log.error('Failed to stop the  traffic: ' % e)
                    self.failed(goto=['cleanup'])
                log.info("cheching the traffic stats and verifying the TX and RX packets")
                try:
                    stats_list = spirent.sth.traffic_stats(port_handle=handle_tx, mode='streams',
                                                           rx_port_handle='all', )
                except Exception as e:
                    log.error('Failed collect the stats and hence verification got failed for the traffic:: %s ' % e)
                    self.failed(goto=['cleanup'])
                for stream in stream_ids[handle_tx]:
                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['rx']:
                        rx_pkts = 0
                    else:
                        rx_pkts = stats_list[handle_tx]['stream'][stream]['rx']['total_pkts']

                    if 'total_pkts' not in stats_list[handle_tx]['stream'][stream]['tx']:
                        tx_pkts = 0
                    else:
                        tx_pkts = stats_list[handle_tx]['stream'][stream]['tx']['total_pkts']
                    rx_pkts = int(rx_pkts)
                    tx_pkts = int(tx_pkts)
                    stats = verify_stats_without_acl(rx_pkts,tx_pkts,traffic_tolerance)
                    if stats :
                        log.info("traffic is passed after removing the ACL")
                    else :
                        log.error("Traffic failed with ACL is removed")
                        self.failed(goto=['cleanup'])
                try:
                    for id in stream_ids[handle_tx]:
                        result = spirent.sth.traffic_config(port_handle=handle_tx, mode='reset', stream_id=id)
                        log.info('result %s' % result)
                        log.info('Traffic removed')
                except Exception as e:
                    log.error('Failed to remove the traffic streams: %e ' % e)
                    self.failed(goto=['cleanup'])
    @aetest.test
    def tc_check_trace_crash(self):
        failure = 0
        # need some clarification
        uut = self.script_args['uut']
        log.info("Verification of show logging and show context location all")
        try:
            res = verify_show_logging_context(uut)
            if not res:
                log.error('Crash Check Failed')
                self.failed()
        except Exception as e:
            log.error(
                'Verification of show logging and show context location all failed in the router %s as %s' % (uut, e))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        uut = self.script_args['uut']
        try:
            log.info("Reset the port configuration to default")
            log.info("removing ACL  configuration")
            conf = self.script_args['unconfig']
            uut.config(conf)
        except Exception as e:
            log.error('Test Clean up is failed: %s ' % e)
            self.failed()


class common_cleanup(aetest.CommonCleanup):
    """ Common Cleanup for Sample Test """

    @aetest.subsection
    def cleanup(self):
        """ Common Cleanup subsection """
        #log.info(banner("script common cleanup starts here"))
        # After all the tests have been run, perform a post_router_check
        # to check that no router failures have occured

        success = True
        #pdb.set_trace()
        if 'tgen_hdls' in self.script_args :
            port_handles = self.script_args['tgen_hdls']
            try:
                cleanup_sta = spirent.sth.cleanup_session(port_handle=port_handles)
                status = cleanup_sta['status']
                if status == '0':
                    log.info("run sth.cleanup_session failed")
                    log.info("cleanup_sta %s" % cleanup_sta)
            except Exception as e:
                log.info('Failed to sth.cleanup_session: %s' % e)
                self.failed()

        uut = self.script_args['uut']
        uut_name = self.script_args['uut_name']
        if 'port_data' in self.script_args :
            interface = self.script_args['port_data']
            neighbor = interface[uut_name]['neighbors']['TGN-SPIRENT']
        log.info('cleainr the router configs')
        log.info("removing ACL  configuration")
        conf = self.script_args['unconfig']
        if conf != '':
            uut.config(conf)
        for indx in neighbor.keys():
            intf = interface[uut_name]['neighbors']['TGN-SPIRENT'][indx]['interface']['name']
            conf = '''
                no interface %s
                no interface %s.*
                interface %s
                no shutdow
                ''' % (intf, intf, intf)
            uut.config(conf)
        uut.config("no l2vpn xconnect group XCON")
        log.info('remove tgn session')
        if success == False:
            self.failed()

if __name__ == '__main__': # pragma: no cover
    aetest.main()

