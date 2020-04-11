
import sth

# lab_server = sth.labserver_connect (
#         server_ip = '10.64.98.93',
#         create_new_session =1,
#         session_name = 'LAG',
#         user_name = 'Tester')
#
# test_sta = sth.test_config (
#             log = '1',
#             logfile = 'vlan_LAG_logfile',
#             vendorlogfile = 'vlan_LAG_stcExport',
#             vendorlog = '1',
#             hltlog = '1',
#             hltlogfile = 'vlan_LAG_hltExport',
#             hlt2stcmappingfile = 'vlan_LAG_hlt2StcMapping',
#             hlt2stcmapping = '1',
#             log_level = '7')

def build_config_vars(type,tgen_pkt_rate,tgen_port_src_mac,tgen_port_dst_mac,pkt_size,hdl):
    traffic_config=dict()
    traffic_config['broadcast']=dict()
    traffic_config['others']=dict()
    traffic_config['broadcast']['common']={'inter_stream_gap_unit':'bytes',
                            'mac_src_count':'1', #doubt mac_src_step equivalent
                            'mac_src_mode':'random',  #doubt fixed not found
                            'length_mode':'fixed',
                            'mac_dst_count':'1', # required mac_dst_step
                            'rate_pps':tgen_pkt_rate,
                            'mac_dst_mode':'random', #doubt fixed not found
                            'l3_portocol':'ipv4',
                            'mac_dst':tgen_port_dst_mac,
                            'enable_stream_only_gen': '0',
                            'inter_stream_gap':'124916.0',
                            'ip_ttl':'64',
                            'frame_size':pkt_size,
                            'mode':'create',
                            'mac_src':tgen_port_src_mac,
                            'port_handle':hdl,
                            'enable_stream':'false'}
    traffic_config['unicat']={'inter_stream_gap_unit':'bytes',
                            'mac_src_count':'1', #doubt mac_src_step equivalent
                            'mac_src_mode':'random',  #doubt fixed not found
                            'length_mode':'fixed',
                            'mac_dst_count':'1', # required mac_dst_step
                            'rate_pps':tgen_pkt_rate,
                            'mac_dst_mode':'random', #doubt fixed not found
                            'l3_portocol':'ipv4',
                            'mac_dst':tgen_port_dst_mac,
                            'enable_stream_only_gen': '0',
                            'inter_stream_gap':'124916.0',
                            'ip_ttl':'64',
                            'frame_size':pkt_size,
                            'mode':'create',
                            'mac_src':tgen_port_src_mac,
                            'port_handle':hdl,
                            'enable_stream':'false'} 							

    traffic_config['broadcast']['cmd1']={}
  
    traffic_config['broadcast']['cmd2']={
                            'l2_encap':'ethernet_ii_vlan',
                            'vlan_id':'9',
                            'vlan_tpid':'33024',
                        }          


    traffic_config['broadcast']['cmd3']={
                            'l2_encap':'ethernet_ii_vlan',
                            'vlan_id':'9',
                            'vlan_tpid':'34984',
                            'frame_size':'76',
                            }          

    traffic_config['broadcast']['cmd4']={
                            'l2_encap':'ethernet_ii_vlan',
                            'vlan_id':'10',
                            'vlan_id_outer':'9',
                            'vlan_outer_tpid':'34984',
                            'vlan_tpid':'33024',
                            }


    traffic_config['broadcast']['cmd5']={
                            'l2_encap':'ethernet_ii_vlan',
                            'vlan_id':'10',
                            'vlan_id_outer':'100',
                            'vlan_tpid':'33024',
                            'vlan_outer_tpid':'33024',
                            'frame_size':'76',
                            }          

    traffic_config['broadcast']['cmd6']={
                            'l2_encap':'ethernet_ii_vlan',
                            'vlan_id':'0',
                            'vlan_tpid':'34984',
                            'vlan_user_priority':'3',
                            'port_handle':'1/1/1'
                            }          
          
    traffic_config['broadcast']['cmd7']={
                            'l2_encap':'ethernet_ii_vlan',
                            'vlan_id':'0',
                            'vlan_tpid':'33024',
                            'vlan_user_priority':'3',
                            }          
    traffic_config['broadcast']['cmd8']={
                            'l2_encap':'ethernet_ii_vlan',
                            'vlan_id': ['100','101','102'], #doubt can this be a list
                            'vlan_tpid':'33024',
                            'vlan_outer_tpid':'34984',
                            }          
    traffic_config['broadcast']['cmd9']={
                            'l2_encap':'ethernet_ii_vlan',
                            'vlan_id':['200','201','202'],
                            'vlan_tpid':'33024',
                            'vlan_outer_tpid':'33024',
                           } 
    traffic_config['others']['common']={'inter_stream_gap_unit':'bytes',
                            'ip_src_mode' : 'fixed',
                            'ip_dst_mode' : 'fixed',
                            'length_mode':'fixed',
                            'mac_dst_count':'1', # required mac_dst_step
                            'rate_pps':tgen_pkt_rate,
                            'mac_dst_mode':'random', #doubt fixed not found
                            'l3_protocol':'ipv4',
                            'enable_stream_only_gen': '0',
                            'inter_stream_gap':'12',
                            'ip_ttl':'64',
                            'frame_size':pkt_size,
                            'mode':'create',
                            'port_handle':hdl,
                            'enable_stream':'false'}          

    traffic_config['others']['cmd1']={}
  
    traffic_config['others']['cmd2']={
                            'l2_encap':'ethernet_ii_vlan',
                            'inter_stream_gap':'1166.0',
                            'vlan_id':'9',
                            'vlan_tpid':'33024',
                        }          


    traffic_config['others']['cmd3']={
                            'l2_encap':'ethernet_ii_vlan',
                            'inter_stream_gap':'1166.0',
                            'vlan_id':'9',
                            'vlan_tpid':'34984',
                            }          

    traffic_config['others']['cmd4']={
                            'l2_encap':'ethernet_ii_vlan',
                            'inter_stream_gap':'124916.0',
                            'vlan_id':'10',
                            'vlan_id_outer':'9',
                            'vlan_outer_tpid':'34984',
                            'vlan_tpid':'33024',
                            }


    traffic_config['others']['cmd5']={
                            'inter_stream_gap':'124916.0',
                            'l2_encap':'ethernet_ii_vlan',
                            'vlan_id':'10',
                            'vlan_id_outer':'100',
                            'vlan_tpid':'33024',
                            'vlan_outer_tpid':'33024',
                            }          

    traffic_config['others']['cmd6']={
                            'l2_encap':'ethernet_ii_vlan',
                            'vlan_id_outer':'9',
                            'vlan_outer_tpid':'34984',
                            'vlan_id':'0',
                            'vlan_tpid':'34984',
                            'vlan_user_priority':'3',
                            'inter_stream_gap':'1166.0',
                            }          
          
    traffic_config['others']['cmd7']={
                            'l2_encap':'ethernet_ii_vlan',
                            'vlan_id_outer':'9',
                            'vlan_outer_tpid':'34984',
                            'vlan_tpid':'33024',
                            'vlan_id':'0',
                            'vlan_tpid':'33024',
                            'vlan_user_priority':'3',
                            'inter_stream_gap':'1166.0',
                            }          
    traffic_config['others']['cmd8']={
                            'vlan_id_outer':'9',
                            'l2_encap':'ethernet_ii_vlan',
                            'vlan_id': ['100','101','102'], #doubt can this be a list
                            'vlan_tpid':'33024',
                            'vlan_outer_tpid':'34984',
                            'inter_stream_gap':'1166.0',
                            }          
    traffic_config['others']['cmd9']={
                            'l2_encap':'ethernet_ii_vlan',
                            'vlan_id_outer':'9',
                            'vlan_id':['200','201','202'],
                            'vlan_tpid':'33024',
                            'vlan_outer_tpid':'34984',
                            'inter_stream_gap':'1166.0',}
    return traffic_config[type]

def generate_traffic(tgen_hdls,time_interval=10):
    try:
        clear_counters()
        result=clear_stats()
        log.info("Clear stats: result %s" % str(result))
        #Applying sleep for 10 sec
        time.sleep(time_interval)
        result=start_traffic(tgen_hdls)
        log.info('Traffic control status : %s' % result['status']) 
        time.sleep(time_interval)
        result=stop_traffic(tgen_hdls)
        log.info('Traffic control status : %s' % result['status']) 
        time.sleep(time_interval)

    except Exception as e:
       log.error('Failed sth.traffic_conrol : %s ' % e)
       self.failed()
 

def clear_counters(uut):
    uut.execute('clear counters')
    return True

def clear_stats():
    result=sth.traffic_control(port_handle=port_handles,action='clear_stats')
    return result

def start_traffic():
    result=sth.traffic_control(port_handle=tgen_hdls,action="run")
    return result

def stop_traffic():
    result=sth.traffic_control(port_handle=tgen_hdls,action="stop")
    return result
    pass



