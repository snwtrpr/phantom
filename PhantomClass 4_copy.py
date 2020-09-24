"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'destination_ip' block
    destination_ip(container=container)

    # call 'Source_ip' block
    Source_ip(container=container)

    return

def DST_Public_Format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('DST_Public_Format() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "destination_ip:custom_function:public_ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="DST_Public_Format")

    Dest_Geolocate(container=container)

    return

"""
Takes the destination IP and separates based on commas
"""
def destination_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('destination_ip() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    destination_ip__private_ip = None
    destination_ip__public_ip = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    import ipaddress
    
    working_addresses = []
    ret_private_addresses = []
    ret_public_addresses = []
    
    for entry in container_item_0:
        if entry:
            if "," in entry:
                split_addr = entry.split(",")
                for addr in split_addr:
                    working_addresses.append(addr)
            else:
                working_addresses.append(entry)
            
    for ip in working_addresses:
        if ipaddress.ip_address(unicode(ip)).is_private:
            ret_private_addresses.append(ip)
        else:
            ret_public_addresses.append(ip)
            
    destination_ip__private_ip = ret_private_addresses
    destination_ip__public_ip = ret_public_addresses
    
    phantom.debug("Destination private ip")
    phantom.debug(destination_ip__private_ip)
    phantom.debug("Destination public ip")
    phantom.debug(destination_ip__public_ip)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='destination_ip:private_ip', value=json.dumps(destination_ip__private_ip))
    phantom.save_run_data(key='destination_ip:public_ip', value=json.dumps(destination_ip__public_ip))
    filter_2(container=container)

    return

"""
Takes the source IP and separates based on commas
"""
def Source_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Source_ip() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    Source_ip__private_ip = None
    Source_ip__public_ip = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import ipaddress
    
    working_addresses = []
    ret_private_addresses = []
    ret_public_addresses = []
    
    for entry in container_item_0:
        if entry:
            if "," in entry:
                split_addr = entry.split(",")
                for addr in split_addr:
                    working_addresses.append(addr)
            else:
                working_addresses.append(entry)
            
    for ip in working_addresses:
        if ipaddress.ip_address(unicode(ip)).is_private:
            ret_private_addresses.append(ip)
        else:
            ret_public_addresses.append(ip)
            
    Source_ip__private_ip = ret_private_addresses
    Source_ip__public_ip = ret_public_addresses
    
    phantom.debug("source private ip")
    phantom.debug(Source_ip__private_ip)
    phantom.debug("source public ip")
    phantom.debug(Source_ip__public_ip)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Source_ip:private_ip', value=json.dumps(Source_ip__private_ip))
    phantom.save_run_data(key='Source_ip:public_ip', value=json.dumps(Source_ip__public_ip))
    filter_1(container=container)

    return

def DST_Reverse_DNS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('DST_Reverse_DNS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'DST_Reverse_DNS' call
    results_data_1 = phantom.collect2(container=container, datapath=['Dest_Geolocate:action_result.parameter.ip', 'Dest_Geolocate:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'DST_Reverse_DNS' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="lookup ip", parameters=parameters, assets=['google_dns'], callback=DST_Public_Comment, name="DST_Reverse_DNS", parent_action=action)

    return

def Dest_Geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Dest_Geolocate() called')

    # collect data for 'Dest_Geolocate' call
    formatted_data_1 = phantom.get_format_data(name='DST_Public_Format__as_list')

    parameters = []
    
    # build parameters list for 'Dest_Geolocate' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'ip': formatted_part_1,
        })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=DST_Reverse_DNS, name="Dest_Geolocate")

    return

"""
Looks up IP from the formatted block
"""
def SRC_Public_Reverse_DNS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('SRC_Public_Reverse_DNS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'SRC_Public_Reverse_DNS' call
    results_data_1 = phantom.collect2(container=container, datapath=['Source_geolocate:action_result.parameter.ip', 'Source_geolocate:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'SRC_Public_Reverse_DNS' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="lookup ip", parameters=parameters, assets=['google_dns'], callback=SRC_Public_Comment, name="SRC_Public_Reverse_DNS", parent_action=action)

    return

def Source_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Source_geolocate() called')

    # collect data for 'Source_geolocate' call
    formatted_data_1 = phantom.get_format_data(name='SRC_Public_Format__as_list')

    parameters = []
    
    # build parameters list for 'Source_geolocate' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'ip': formatted_part_1,
        })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=SRC_Public_Reverse_DNS, name="Source_geolocate")

    return

def SRC_Public_Format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('SRC_Public_Format() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Source_ip:custom_function:public_ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="SRC_Public_Format")

    Source_geolocate(container=container)

    return

def DST_Public_Comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('DST_Public_Comment() called')
    
    template = """%%
IP:{0}
Destination
country:{1}
DNS:{2}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "DST_Reverse_DNS:action_result.summary.ip",
        "Dest_Geolocate:action_result.data.*.country_iso_code",
        "DST_Reverse_DNS:action_result.summary.hostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="DST_Public_Comment")

    dstPublicArtifacts(container=container)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["Source_ip:custom_function:public_ip", "!=", []],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        SRC_Public_Format(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["Source_ip:custom_function:private_ip", "!=", []],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        SRC_Private_Format(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def SRC_Private_Format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('SRC_Private_Format() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Source_ip:custom_function:private_ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="SRC_Private_Format")

    SRC_Private_Reverse_DNS(container=container)

    return

def SRC_Private_Reverse_DNS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('SRC_Private_Reverse_DNS() called')

    # collect data for 'SRC_Private_Reverse_DNS' call
    formatted_data_1 = phantom.get_format_data(name='SRC_Private_Format__as_list')

    parameters = []
    
    # build parameters list for 'SRC_Private_Reverse_DNS' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'ip': formatted_part_1,
        })

    phantom.act(action="lookup ip", parameters=parameters, assets=['google_dns'], callback=SRC_Private_Comment, name="SRC_Private_Reverse_DNS")

    return

def SRC_Public_Comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('SRC_Public_Comment() called')
    
    template = """%%
IP:{0}
Source
country:{1}
DNS:{2}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "SRC_Public_Reverse_DNS:action_result.parameter.ip",
        "Source_geolocate:action_result.data.*.country_iso_code",
        "SRC_Public_Reverse_DNS:action_result.summary.hostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="SRC_Public_Comment")

    adding_comment_artifacts(container=container)

    return

def SRC_Private_Comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('SRC_Private_Comment() called')
    
    template = """%%
IP: {0}
Source
DNS: {1}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "SRC_Private_Reverse_DNS:action_result.parameter.ip",
        "SRC_Private_Reverse_DNS:action_result.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="SRC_Private_Comment")

    srcPrivateArtifacts(container=container)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["destination_ip:custom_function:public_ip", "!=", []],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        DST_Public_Format(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["destination_ip:custom_function:private_ip", "!=", []],
        ],
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        DST_Private_Format(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def DST_Private_Format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('DST_Private_Format() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "destination_ip:custom_function:private_ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="DST_Private_Format")

    DST_Private_Reverse_DNS(container=container)

    return

def DST_Private_Reverse_DNS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('DST_Private_Reverse_DNS() called')

    # collect data for 'DST_Private_Reverse_DNS' call
    formatted_data_1 = phantom.get_format_data(name='DST_Private_Format__as_list')

    parameters = []
    
    # build parameters list for 'DST_Private_Reverse_DNS' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'ip': formatted_part_1,
        })

    phantom.act(action="lookup ip", parameters=parameters, assets=['google_dns'], callback=DST_Private_Comment, name="DST_Private_Reverse_DNS")

    return

def DST_Private_Comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('DST_Private_Comment() called')
    
    template = """%%
IP: {0}
Destination
DNS: {1}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "DST_Private_Reverse_DNS:action_result.parameter.ip",
        "DST_Private_Reverse_DNS:action_result.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="DST_Private_Comment")

    dstPrivateArtifacts(container=container)

    return

def adding_comment_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('adding_comment_artifacts() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['SRC_Public_Reverse_DNS:action_result.parameter.ip', 'SRC_Public_Reverse_DNS:action_result.summary.hostname'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['Source_geolocate:action_result.data.*.country_iso_code'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]

    adding_comment_artifacts__comments = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    ip_address = results_item_1_0
    dns_hostname = results_item_1_1
    country_code = results_item_2_0
    
    phantom.debug(ip_address)
    phantom.debug(dns_hostname)
    phantom.debug(country_code)
    
    cef = {}
    cef['sourceAddress'] = ip_address
    cef['sourceDnsDomain'] = dns_hostname
    cef['countryCode'] = country_code

    success, message, artifact_id = phantom.add_artifact(
        container=container,
        raw_data=None,
        cef_data=cef,
        label="comment",
        name="Source Public IP",
        severity="medium",
        identifier=None,
        artifact_type=None,
        field_mapping=None, 
        trace=False,
        run_automation=False)
    
    phantom.debug('artifact added as id: '+str(artifact_id))
    
    return

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='adding_comment_artifacts:comments', value=json.dumps(adding_comment_artifacts__comments))
    join_playbook_local_local_Message_Print_1(container=container)

    return

def srcPrivateArtifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('srcPrivateArtifacts() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['SRC_Private_Reverse_DNS:action_result.parameter.ip', 'SRC_Private_Reverse_DNS:action_result.summary.hostname'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    ip_address = results_item_1_0
    dns_hostname = results_item_1_1

    phantom.debug(ip_address)
    phantom.debug(dns_hostname)

    cef = {}
    cef['sourceAddress'] = ip_address
    cef['sourceDnsDomain'] = dns_hostname

    success, message, artifact_id = phantom.add_artifact(
        container=container,
        raw_data=None,
        cef_data=cef,
        label="comment",
        name="Source Private IP",
        severity="medium",
        identifier=None,
        artifact_type=None,
        field_mapping=None, 
        trace=False,
        run_automation=False)
    
    phantom.debug('artifact added as id: '+str(artifact_id))

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_playbook_local_local_Message_Print_1(container=container)

    return

def dstPublicArtifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('dstPublicArtifacts() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['DST_Reverse_DNS:action_result.parameter.ip', 'DST_Reverse_DNS:action_result.summary.hostname'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['Dest_Geolocate:action_result.data.*.country_iso_code'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    ip_address = results_item_1_0
    dns_hostname = results_item_1_1
    country_code = results_item_2_0
    
    phantom.debug(ip_address)
    phantom.debug(dns_hostname)
    phantom.debug(country_code)
    
    cef = {}
    cef['destinationAddress'] = ip_address
    cef['destinationDnsDomain'] = dns_hostname
    cef['countryCode'] = country_code

    success, message, artifact_id = phantom.add_artifact(
        container=container,
        raw_data=None,
        cef_data=cef,
        label="comment",
        name="Destination Public IP",
        severity="medium",
        identifier=None,
        artifact_type=None,
        field_mapping=None, 
        trace=False,
        run_automation=False)
    
    phantom.debug('artifact added as id: '+str(artifact_id))

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_playbook_local_local_Message_Print_1(container=container)

    return

def dstPrivateArtifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('dstPrivateArtifacts() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['DST_Private_Reverse_DNS:action_result.parameter.ip', 'DST_Private_Reverse_DNS:action_result.summary.hostname'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    ip_address = results_item_1_0
    dns_hostname = results_item_1_1

    phantom.debug(ip_address)
    phantom.debug(dns_hostname)

    cef = {}
    cef['destinationAddress'] = ip_address
    cef['destinationDnsDomain'] = dns_hostname

    success, message, artifact_id = phantom.add_artifact(
        container=container,
        raw_data=None,
        cef_data=cef,
        label="comment",
        name="Destination Private IP",
        severity="medium",
        identifier=None,
        artifact_type=None,
        field_mapping=None, 
        trace=False,
        run_automation=False)
    
    phantom.debug('artifact added as id: '+str(artifact_id))

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_playbook_local_local_Message_Print_1(container=container)

    return

def playbook_local_local_Message_Print_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_local_Message_Print_1() called')
    
    # call playbook "local/Message Print", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/Message Print", container=container, name="playbook_local_local_Message_Print_1")

    return

def join_playbook_local_local_Message_Print_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_playbook_local_local_Message_Print_1() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['SRC_Public_Reverse_DNS', 'SRC_Private_Reverse_DNS', 'DST_Reverse_DNS', 'DST_Private_Reverse_DNS']):
        
        # call connected block "playbook_local_local_Message_Print_1"
        playbook_local_local_Message_Print_1(container=container, handle=handle)
    
    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return