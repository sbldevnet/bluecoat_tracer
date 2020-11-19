#!/bin/python3

"""
How To
------
    1. Add API_URL and FILE_PATH variables to vars.py file
    2. Exec pip install -r requirements.txt
    2. Exec python3 bluecoat_tracer.py

Limitations
-----------
    Only check UserAuthenticationPolicyTable & WebAccessPolicyTable layers
    Not check if "negate" check is in policy
    Not check Threat Risk Level (TL) (Not available in API)
"""

# Import dependencies
import xml.etree.ElementTree as ET
import ipaddress
import sys
import logging
from urllib.parse import urlparse
import re
from getpass import getpass
import requests
import urllib3
# Import var file
from vars import *

# Disable HTTPS server certificate exception terminal output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global variables
AUTH_METHOD = ''
PROXY_PORT = proxy_port

# Define Colors
class bcolors:
    """Output colors"""
    BLUE    = '\033[1;36m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    RED     = '\033[91m'
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    # UNDERLINE = '\033[4m'

# Check python version
if sys.version_info[0] < 3:
    sys.exit(f"{bcolors.RED}Upgrade Python version{bcolors.RESET}")

# Set Log
if sys.version_info[1] < 9:
    logging.basicConfig(filename=LOG_FILE_NAME, level=logging.DEBUG, \
        format='%(asctime)s - %(levelname)s - %(message)s') # for python <3.9
else:
    logging.basicConfig(filename=LOG_FILE_NAME, encoding='utf-8', level=logging.DEBUG, \
        format='%(asctime)s - %(levelname)s - %(message)s') # add encoding in python >=3.9


# Init Banner
print()
print(f"{bcolors.BLUE}")
print("#####################################")
print("##  Symantec ProxySG Utility Tool  ##")
print("#####################################")
print(f"{bcolors.GREEN}", end="")
print("https://github.com/sburgosl")
print()


##############################
# Main menu
##############################
logging.debug("START SCRIPT")

def main():
    """
    Description:
        Main menu
    """
    logging.debug("Exec: main()")

    print()
    print(f"{bcolors.BLUE}[GLOBAL VARIABLES]{bcolors.RESET}")
    print("Auth method: " + AUTH_METHOD)
    print("Proxy Port: " + str(PROXY_PORT))
    print("Exclude layers: " + str(EXCLUDE_LAYERS))
    print()
    print(f"{bcolors.BLUE}[OPTIONS]{bcolors.RESET}")
    print("[1]: Search source IP match")
    print("[2]: Search destination (IP/FQDN/URL)")
    print("[3]: Search source/destination")
    print("[4]: Get / Select authentication")
    print("[5]: Select proxy port")
    print("[6]: Download policy xml")
    print("[0]: Exit")
    print("Select Option: ", end="")

    try:
        option = int(input())
        switcher = {
            1: menu_search_source_ip,
            2: menu_search_dest,
            3: search_complete,
            4: edit_auth,
            5: edit_proxy_port,
            6: menu_download_policy,
            0: sys.exit
        }
        switcher.get(option, main)()

    except ValueError as e:
        msg_wrn("Not valid input")
        logging.warning("Not int on main() input: " + str(e))

    except KeyboardInterrupt:
        sys.exit("")

    except Exception as e:
        logging.critical(e)
        sys.exit('Error')

    main()


##############################
# [1]: Search source IP match
##############################
# OK
def menu_search_source_ip():
    """
    Description:
        Dispalys the policy rules that match with a source IP
    """
    logging.debug("Exec: menu_search_source_ip()")

    root = get_xml_root()
    try:
        print("\nEnter source IP: ", end="")
        input_src = ipaddress.ip_address(input())

        print_start()

        # Get all ipobjects that matches with source ip
        match_ipobjects = get_xml_ipobject_match(root, input_src)

        # Get comb-obj that contains match_ipbojects. This improves efficency
        match_comb_obj = get_xml_com_obj_match(root, match_ipobjects)

        layers_enabled = get_xml_policy_layers(root)
        for layer in layers_enabled:
            if layer.attrib.get('layertype') == 'com.bluecoat.sgos.vpm.UserAuthenticationPolicyTable' \
            or layer.attrib.get('layertype') == 'com.bluecoat.sgos.vpm.WebAccessPolicyTable':
                get_rows_src_match(layer, match_ipobjects, match_comb_obj, False, [], urlparse(''))
        
        print_end()

    except ValueError as e:
        logging.warning("Input menu_search_source_ip() is not ipadress:" + str(e))
        msg_wrn("Input not valid")
        menu_search_source_ip()


##############################
# [2]: search_dest
##############################

def menu_search_dest():
    """
    Description:
        Get user and password
        Get custom and Symantec predefined Categories from proxy node
    """
    logging.debug("Exec: menu_search_dest()")

    # Ask User & Pass
    print("Enter User: ", end="")
    user = input()
    print("Enter Pass: ", end="")
    password = getpass()
    rtext = get_proxy_categories(user,password)
    print(rtext)
    if "Error" in str(rtext):
        logging.error("Error in response in menu_search_dest()" + str(rtext))
        msg_sys(str(rtext))
    else:
        print()
        policy = rtext[0].rsplit(':',1)[1].strip()
        bluecoat = rtext[1].rsplit(':',1)[1].strip()
        print(policy)
        print(bluecoat)

    main()


def get_proxy_categories(user, password):
    """
    Description:
        Get custom and Symantec predefined Categories from proxy node
    Input:
        user        - (String) user of symantec management center
        password    - (String) password of symantec management center
    Output:
        rtext       - (String) HTTP Response categories in text
        
    """
    logging.debug("Exec: get_proxy_categories()")

    try:
        req = requests.get(NODE_URL+"ContentFilter/TestUrl/google.es", verify=False, auth=(user, password))
        logging.info("HTTP Status code in get_proxy_categories() + '" + str(req.status_code) + "'")

        if req.status_code == 200:
            rtext = req.text.strip().split('\n')
            return rtext

        elif req.status_code == 401:
            sys.exit(f"{bcolors.RED}Authentication Error{bcolors.RESET}")

        elif req.status_code == 403:
            sys.exit(f"{bcolors.RED}Forbidden{bcolors.RESET}")

        else:
            logging.error("Status Code not handled in get_proxy_categories()")
            sys.exit(f"{bcolors.RED}Connection Error{bcolors.RESET}: see logs for more info")

    except ValueError as e:
        logging.error("Error in response in get_proxy_categories()" + str(e))

    except requests.exceptions.ConnectionError as e:
        logging.error("Connection error in get_proxy_categories(): " + str(e))

    except Exception as e:
        logging.error("Error not handled in get_proxy_categories(): " + str(e))

    sys.exit(f"{bcolors.RED}Connection Error{bcolors.RESET}: see logs for more info")


##############################
# [3]: search_complete
##############################

def search_complete():
    """
    """
    logging.debug("Exec: search_complete()")

    root = get_xml_root()

    try:
        print("\nEnter source IP: ", end="")
        input_src = ipaddress.ip_address(input())

        print("Enter destination in URL Format. Example '//192.168.1.1' or 'http://google.es:443/test.jpg': ", end="")
        input_dest = urlparse(input())

        if input_dest.netloc == '':
            print('[Error]: Destination is not in URL format')
            logging.warning("Input destination search_complete() is not URL:" + str(input_dest))

        else:
            print_start()

            # Get all ipobjects that matches with source ip
            match_ipobjects = get_xml_ipobject_match(root, input_src)

            # Get comb-obj that contains match_ipbojects
            match_comb_obj = get_xml_com_obj_match(root, match_ipobjects)

            ###################################
            ####### GET CATEGORIES ############
            ###################################
            dst_categories = ['Test_Category']
            ##################################

            layers_enabled = get_xml_policy_layers(root)

            for layer in layers_enabled:
                if layer.attrib.get('layertype') == 'com.bluecoat.sgos.vpm.UserAuthenticationPolicyTable' or layer.attrib.get('layertype') == 'com.bluecoat.sgos.vpm.WebAccessPolicyTable':
                    get_rows_src_match(layer, match_ipobjects, match_comb_obj, True, dst_categories, input_dest)

            print_end()

    except ValueError as e:
        logging.warning("Input search_complete() is not ipadress:" + str(e))
        search_complete()

    main()


##############################
# [4]: edit_auth
##############################

def edit_auth():
    """
    List and select authentication groups
    """

    logging.debug("Exec: edit_auth()")

    root = get_xml_root()
    auth_groups = root.findall('conditionObjects/group')

    print()
    i = 0
    for auth_group in auth_groups:
        auth_group_base     = auth_group.attrib.get('group-base')
        auth_group_location = auth_group.attrib.get('group-location')
        auth_realm_name     = auth_group.attrib.get('realm-name')
        print( "[" + str(i) + "] " + auth_realm_name + " - " + auth_group_location + " / " + auth_group_base )
        i += 1

    print("Select Authentication: ", end="")

    try:
        auth_select = auth_groups[int(input())].attrib.get('group-base')
        global AUTH_METHOD
        AUTH_METHOD = auth_select
        logging.info("Change authentication method value to '" + AUTH_METHOD + "'")

    except IndexError as e:
        logging.warning("Out of index on edit_auth() input: " + str(e))

    main()


##############################
# [5]: edit_proxy_port
##############################

def edit_proxy_port():
    """
    Edit proxy_port value. Default proxy_port value is defined in vars.py file
    """

    logging.debug("Exec: edit_proxy_port()")

    try:
        print("Insert proxy port: ", end="")
        global PROXY_PORT
        PROXY_PORT = int(input())
        print()

        logging.info("Change proxy port value to '" + str(PROXY_PORT) + "'")

    except ValueError as error:
        logging.warning("Not int in edit_proxy_port() input: " + str(error))

    main()


##############################
# [6]: menu_download_policy
##############################

# OK
def menu_download_policy():
    """
    Description:
        Get user and password
        List and select policies
        List and select versions
        Download selected policy version
    """
    logging.debug("Exec: menu_download_policy()")

    # Ask User & Pass
    print("Enter User: ", end="")
    user = input()
    print("Enter Pass: ", end="")
    password = getpass()
    policies = get_proxy_policies(user,password)
    print()

    for policy in policies:
        print("Policy uuid: '" + policy['uuid'] + "' Name: '" + policy['name'] + "' Desc: '" + policy['description'] + "'")

    # Ask uuid
    print("Enter Policy uuid: ", end="")
    policy_uuid = input()
    versions = get_proxy_policy_versions(user, password, policy_uuid)
    for version in versions:
        print("Version: '" + version['revisionNumber'] + "' Date: '" + version['revisionDate'] + "' : '" + version['revisionDescription'] + "'")

    # Ask version
    print("Enter Version: ", end="")
    revision = input()
    get_proxy_policy_download(user, password, policy_uuid, revision)
    print(f"{bcolors.GREEN}[OK]{bcolors.RESET}")

    main()

# OK
def get_proxy_policies(user, password):
    """
    Description:
        List and select policy from Symantec Management Center using API
    Input:
        user        - (String) user of symantec management center
        password    - (String) password of symantec management center
    Output:
        policies    - (String) json array policies response
    """
    logging.debug("Exec: get_proxy_policies()")

    try:
        req = requests.get(API_URL+"policies/", verify=False, auth=(user, password))
        logging.info("HTTP Status code in get_proxy_policies() + '" + str(req.status_code) + "'")

        if req.status_code == 200:
            return req.json()

        elif req.status_code == 401:
            sys.exit(f"{bcolors.RED}Authentication Error{bcolors.RESET}")

        elif req.status_code == 403:
            sys.exit(f"{bcolors.RED}Forbidden{bcolors.RESET}")

        else:
            logging.error("Status Code not handled in get_proxy_policies()")
            sys.exit(f"{bcolors.RED}Connection Error{bcolors.RESET}: see logs for more info")

    except ValueError as e:
        logging.error("Error in response in get_proxy_policies()" + str(e))

    except requests.exceptions.ConnectionError as e:
        logging.error("Connection error in get_proxy_policies(): " + str(e))

    except Exception as e:
        logging.error("Error not handled in get_proxy_policies(): " + str(e))

    sys.exit(f"{bcolors.RED}Connection Error{bcolors.RESET}: see logs for more info")

# OK
def get_proxy_policy_versions(user, password, policy_uuid):
    """
    Description:
        List and select policy versions from Symantec Management Center using API
    Input:
        user        - (String) user of symantec management center
        password    - (String) password of symantec management center
        policy_uuid - (String) uuid of selected policy
    Output:
        versions    - (String) json array versions response
    """
    logging.debug("Exec: get_proxy_policy_versions()")

    try:
        req = requests.get(API_URL+"policies/"+policy_uuid+"/versions/", verify=False, auth=(user, password))
        logging.info("HTTP Status code in get_proxy_policy_versions() + '" + str(req.status_code) + "'")

        if req.status_code == 200:
            return req.json()

        elif req.status_code == 401:
            print(f"{bcolors.RED}Authentication Error{bcolors.RESET}")
        elif req.status_code == 403:
            print(f"{bcolors.RED}Forbidden{bcolors.RESET}")
        else:
            logging.error("Status Code not handled in get_proxy_policy_versions()")

    except ValueError as e:
        logging.error("Error in response in get_proxy_policy_versions()" + str(e))

    except requests.exceptions.ConnectionError as e:
        logging.error("Connection error in get_proxy_policy_versions(): " + str(e))

    except Exception as e:
        logging.error("Error not handled in get_proxy_policy_versions(): " + str(e))

    sys.exit(f"{bcolors.RED}Connection Error{bcolors.RESET}: see logs for more info")

# OK
def get_proxy_policy_download(user, password, policy_uuid, revision):
    """
    Description:
        Download and save policy xml
    Input:
        user        - (String) user of symantec management center
        password    - (String) password of symantec management center
        policy_uuid - (String) uuid of selected policy
        revision    - (String) revisionNumber of selected policy version
    """
    logging.debug("Exec: get_proxy_policy_download()")

    try:
        req = requests.get(API_URL+"policies/"+policy_uuid+"/content/"+revision, verify=False, auth=(user, password))
        logging.info("HTTP Status code in get_proxy_policy_download() + '" + str(req.status_code) + "'")

        if req.status_code == 200:
            data = req.json()
            content = data['content']['xml']
            file = open(FILE_PATH, 'w')
            file.write(content)
            file.close()
            return

        elif req.status_code == 401:
            print(f"{bcolors.RED}Authentication Error{bcolors.RESET}")
        elif req.status_code == 403:
            print(f"{bcolors.RED}Forbidden{bcolors.RESET}")
        else:
            logging.error("Status Code not handled in get_proxy_policy_download()")

    except ValueError as e:
        logging.error("Error in response in get_proxy_policy_download()" + str(e))

    except requests.exceptions.ConnectionError as e:
        logging.error("Connection error in get_proxy_policy_download(): " + str(e))

    except Exception as e:
        logging.error("Error not handled in get_proxy_policy_versions(): " + str(e))

    sys.exit(f"{bcolors.RED}Connection Error{bcolors.RESET}: see logs for more info")


##############################
# XML Methods
##############################

# OK
def get_xml_root():
    """
    Description:
        Get xml tree root 
    Output:
        policy_xml_root - (XML Element) XML root
    """
    try:
        policy_xml = ET.parse(FILE_PATH)
        policy_xml_root = policy_xml.getroot()
        return policy_xml_root

    except OSError as e:
        logging.error("No such file in get_xml_root() " + str(e))
        sys.exit(f"{bcolors.RED}No such xml file{bcolors.RESET}: Edit variable FILE_PATH in vars.py file or download with option [6]")
    

def get_xml_object_type(object_search):
    """
    Return xml object type
    """

    # logging.debug("Exec: get_xml_object_type() for '" + object_search + "'")

    root = get_xml_root()
    object_type = root.find('conditionObjects/*[@name="'+ object_search +'"]').tag
    
    # logging.debug("Object '" + object_search + "' XML Type '" + object_type + "'")

    return object_type

# OK
def get_xml_ipobject_match(root, input_src):
    """
    Description:
        Search match in ipobject and return name list
    Input:
        root        - (XML Element) XML root
        input_src   - (ipaddress)   source IP address
    Output:
        match_ipobjects - (String List) XML ipobjects names that include input_src IP
    """
    logging.debug("Exec: get_xml_ipobject_match()")
    logging.debug("Source IP: " +  str(input_src))

    match_ipobjects = []
    for ipobject in root.findall('conditionObjects/ipobject'):
        if input_src in ipaddress.ip_network(ipobject.attrib.get('value'), False):
            ipobject_name = ipobject.attrib.get('name')
            ipobject_subnet = ipobject.attrib.get('value')
            match_ipobjects.append(ipobject_name)
            logging.info("Found match. Subnet '" + ipobject_subnet + "'  Name '" + ipobject_name + "'")
        
    return match_ipobjects

# OK
def get_xml_com_obj_match(root, match_ipobjects):
    """
    Description:
        Search comb-obj that contains ipobjects
    Input:
        root            - (XML Element) XML root
        match_ipobjects - (String List) XML ipobjects names that include input_src IP
    Output:
        match_comb_obj  - (String List) XML comb_obj names that include some match_ipobjects
    """
    logging.debug("Exec: get_xml_com_obj_match()")

    match_comb_obj = []
    for ipobject in match_ipobjects:
        comb_objs = root.findall('conditionObjects/comb-obj/c-l-1[@n="' + ipobject + '"]...')
        for comb_obj in comb_objs:
            comb_obj_name = comb_obj.attrib.get('name')
            logging.info("Found comb-obj match. Name '" + comb_obj_name + "'")
            match_comb_obj.append(comb_obj_name)

    return match_comb_obj


def get_comb_obj_content(name):
    """ 
    Search content of combinated object and return array
    """

    logging.debug("Exec: get_comb_obj_content() for '" + name + "'")

    root = get_xml_root()
    comb_obj_content = []

    for content in root.find('conditionObjects/comb-obj[@name="'+name+'"]').iter('c-l-1'):
        comb_obj_content.append(content.attrib.get('n'))

    return comb_obj_content


def get_proxy_port_xml(proxy_object):
    """
    Get proxy port from proxy object name.
    Return number port (int)
    """

    logging.debug("Exec: get_proxy_port_xml() for '" + proxy_object + "'")

    root = get_xml_root()
    proxy_port_xml = int(root.find("conditionObjects/proxy[@name='"+proxy_object+"']").attrib.get('port'))
    return proxy_port_xml


def get_auth_group_base(group_name):
    """
    Get authentication group-base from group name.
    Return group-base (String)
    """

    logging.debug("Exec: get_auth_group_base() for '" + group_name + "'")

    root = get_xml_root()
    auth_group_base = root.find('conditionObjects/group').attrib.get('group-base')
    return auth_group_base


def get_categorylist4_content(categorylist4_name):
    """
    Get vpm-cat in categorylist4 object.
    Return vpm_cat_list (string array) 
    """

    logging.debug("Exec: get_categorylist4_content() for '" + categorylist4_name + "'")

    root = get_xml_root()
    vpm_cat_list = []
    vpm_cat_list_xml = root.findall("conditionObjects/categorylist4[@name='" + categorylist4_name + "']/sel/i")
    for vpm_cat in vpm_cat_list_xml:
        vpm_cat_list.append(vpm_cat.text)

    return vpm_cat_list


def get_auth_obj_match(auth_obj_name):
    """
    Check if xml auth-obj match with selected AUTH_METHOD (group in xml)
    Return boolean
    """

    logging.debug("Exec: get_auth_obj_match()")

    root = get_xml_root()
    realm_search = root.find("conditionObjects/auth-obj[@name='" + auth_obj_name + "']").attrib.get('r-n')

    if AUTH_METHOD == '':
        return False
    else:
        realm_select = root.find("conditionObjects/group[@group-base='" + AUTH_METHOD + "']").attrib.get('realm-name')

    if realm_search == realm_select:
        return True
    else:
        return False


def get_adm_auth_obj_match(auth_obj_name):
    """
    Check if xml adm-auth-obj match with selected AUTH_METHOD (group in xml)
    Return boolean
    """

    logging.debug("Exec: get_adm_auth_obj_match()")

    root = get_xml_root()
    realm_search = root.find("conditionObjects/adm-auth-obj[@name='" + auth_obj_name + "']").attrib.get('r-n')

    if AUTH_METHOD == '':
        return False
    else: 
        realm_select = root.find("conditionObjects/group[@group-base='" + AUTH_METHOD + "']").attrib.get('realm-name')
    
    if realm_search == realm_select:
        return True
    else:
        return False


def get_a_url_match(xml_object_name, destination):
    """
    Check if xml a-url match with input destination
    Return boolean
    """

    logging.debug("Exec: get_a_url_match() for '" + xml_object_name + "'")
    root = get_xml_root()

    xml_h = root.find("conditionObjects/a-url[@name='" + xml_object_name + "']").attrib.get('h')
    xml_p = root.find("conditionObjects/a-url[@name='" + xml_object_name + "']").attrib.get('p')

    if not xml_h == None:
        xml_h_t = root.find("conditionObjects/a-url[@name='" + xml_object_name + "']").attrib.get('h-t')
        if xml_h_t == 'exact-phrase':
            if not destination.hostname == xml_h: return False
        elif xml_h_t == 'at-end':
            if not destination.hostname.endswith(xml_h): return False
        elif xml_h_t == 'at-beginning':
            if not destination.hostname.startswith(xml_h): return False
        elif xml_h_t == 'regex':
            if not re.match(xml_h, destination.hostname): return False
        elif xml_h_t == 'contains':
            if not xml_h in destination.hostname: return False

        else:
            logging.warning("a-url '" + xml_h_t + "' host condition (h-t in xml) not implemented in get_a_url_match()")

    if not xml_p == None:
        xml_p_t = root.find("conditionObjects/a-url[@name='" + xml_object_name + "']").attrib.get('p-t')
        if xml_p_t == 'exact-phrase':
            return destination.path == xml_p
        elif xml_p_t == 'at-end':
            return destination.path.endswith(xml_p)
        elif xml_p_t == 'at-beginning':
            return destination.path.startswith(xml_p)
        elif xml_p_t == 'regex': 
            return bool(re.match(xml_p, destination.path))
        elif xml_p_t== 'contains':
            return xml_p in destination.path
        else:
            logging.warning("a-url '" + xml_p_t + "' path condition (p-t in xml) not implemented in get_a_url_match()")
            return False
    else:
        return True

# OK
def get_xml_policy_layers(root):
    """
    Description:
        Get all layers enabled and not exclued in var exclude_layers.
    Input:
        root            - (XML Element) XML root
    Output:
        layers_enabled  - (XML List) Policy layers enabled
    """
    logging.debug("Exec: get_xml_policy_layers()")

    layers_enabled = []
    for layer in root.findall('layers/layer'):
        if not layer.attrib.get('disabled') == 'true':
            layer_type = layer.attrib.get('layertype')
            layer_name = layer.find('name').text.strip(' \n\t')
            logging.debug("Layertype '%s' Layer Name '%s'",layer_type, layer_name)
            if not layer_name in EXCLUDE_LAYERS:
                layers_enabled.append(layer)

    return layers_enabled



def get_xml_src_row_match():
    """
    """

def get_rows_src_match(layer, match_ipobjects, match_comb_obj, search_dst, dst_categories, input_dest):
    """
    Description:
        Check if src match in layers
    Input:
        search_dst  - (Boolean) True, check destination get_rows_dst_match()
                                False, print match row print_layer_row() 
    """
    logging.debug("Exec: get_rows_src_match()")

    # Check guard
    # guard = layer.find('guard') 
    # if not guard == None:
    #     if not row.attrib.get('enabled') == 'false':


    # Get rows enabled in layer
    for row in layer.findall('rowItem'):
        if not row.attrib.get('enabled') == 'false':
            row_src = row.find('colItem[@id="so"]').attrib.get('name')

            # Check if src is any, ipobject or comb-obj first level
            if row_src == 'Any' or row_src in match_ipobjects or row_src in match_comb_obj:
                if not search_dst:
                    print_layer_row(layer, row, search_dst)
                else:
                    get_rows_dst_match(layer, row, dst_categories, input_dest)

            else:
                object_type = get_xml_object_type(row_src)          
                if object_type == 'comb-obj':
                    comb_obj = get_comb_obj_content(row_src)
                    for c_l_1 in comb_obj:
                        c_l_1_type = get_xml_object_type(c_l_1)

                        if c_l_1_type == 'comb-obj':
                            if c_l_1 in match_comb_obj:
                                if not search_dst:
                                    print_layer_row(layer, row, search_dst)
                                else:
                                    print("WIP")

                        elif c_l_1_type == 'proxy':
                            proxy_port_xml = get_proxy_port_xml(c_l_1)
                            if proxy_port_xml == PROXY_PORT:
                                if not search_dst:
                                    print_layer_row(layer, row, search_dst)
                                else:
                                    print("WIP")
                            
                        else:
                            if not c_l_1_type == 'ipobject': # ignore ipobject in comb-obj (first level). Already in match_comb_obj
                                logging.warning("Object type '" +c_l_1_type + "' not parsing in get_rows_src_match() comb-obj loop")

                elif object_type == 'proxy':
                    proxy_port_xml = get_proxy_port_xml(row_src)
                    if proxy_port_xml == PROXY_PORT:
                        if not search_dst:
                            print_layer_row(layer, row, search_dst)
                        else:
                            print("WIP")

                elif object_type == 'group':
                    auth_group_base = get_auth_group_base(row_src)
                    if auth_group_base == AUTH_METHOD:
                        if not search_dst:
                            print_layer_row(layer, row, search_dst)
                        else:
                            print("WIP")

                else:
                    if not object_type == 'ipobject': # Ignore ipobjects. Already in match_ipobjects
                        logging.warning("Object type '" +object_type + "' not parsing in get_rows_src_match()")


def get_rows_dst_match(layer, row, dst_categories, input_dest):
    """
    Check if input dst match with row destination.
    If match print layer row print_layer_row()
    """

    logging.debug("Exec: get_rows_dst_match()")
    row_dst = row.find('colItem[@id="de"]').attrib.get('name')

    if row_dst == 'Any' or row_dst in dst_categories:
        print_layer_row(layer, row, True)

    else:
        object_type = get_xml_object_type(row_dst)

        if object_type == 'categorylist4':
            dst_row_cats = get_categorylist4_content(row_dst)
            for dst_row_cat in dst_row_cats:
                if dst_row_cat in dst_categories:
                    print_layer_row(layer, row, True)

        elif object_type == 'a-url':
            if get_a_url_match(row_dst, input_dest):
                print_layer_row(layer, row, True)

        elif object_type == 'comb-obj':
            comb_obj = get_comb_obj_content(row_dst)
            for c_l_1 in comb_obj:
                c_l_1_type = get_xml_object_type(c_l_1)

                if c_l_1_type == 'categorylist4':
                    dst_row_cats = get_categorylist4_content(c_l_1)
                    for dst_row_cat in dst_row_cats:
                        if dst_row_cat in dst_categories:
                            print_layer_row(layer, row, True)
                elif c_l_1_type == 'a-url':
                    if get_a_url_match(c_l_1, input_dest):
                        print_layer_row(layer, row, True)
                else:
                    logging.warning("Object type '" +c_l_1_type + "' with name '" + c_l_1 + "' not parsing in get_rows_dst_match() com-obj loop")

        else:
            logging.warning("Object type '" +object_type + "' with name '" + row_dst + "' not parsing in get_rows_dst_match()")


def print_layer_row(layer, row, search_dst):
    """
    Print match row
    If search_dst == True, check if action is ✓ or X and print
    """

    layer_name = layer.find('name').text.strip(' \n\t')
    col_no = row.find('colItem[@id="no"]').attrib.get('value')
    col_so = row.find('colItem[@id="so"]').attrib.get('name')
    col_de = row.find('colItem[@id="de"]').attrib.get('name')
    col_ac = row.find('colItem[@id="ac"]').attrib.get('name')
    col_co = row.find('colItem[@id="co"]').attrib.get('name')

    match = ''
    if search_dst:
        if col_ac == 'Do Not Authenticate': match = '✓'
        elif col_ac == 'Allow': match = '✓'
        elif col_ac == 'Force Deny (Content Filter)': match = 'X'
        elif col_ac == 'Force Deny': match = 'X'
        else: 
            dst_object_type = get_xml_object_type(col_ac)

            if dst_object_type == 'auth-obj':
                if get_auth_obj_match(col_ac):
                    match = '✓'
                else:
                    match = 'X'
            elif dst_object_type == 'adm-auth-obj':
                if get_adm_auth_obj_match(col_ac):
                    match = '✓'
                else:
                    match = 'X'
            else:
                logging.warning("Object type '" +dst_object_type + "' not parsing in print_layer_row()")
    else:
        col_so = f"{bcolors.BLUE}" + col_so + f"{bcolors.RESET}"


    logging.info("Match on Layer: " + layer_name + " Row: " + col_no + " Src: " + col_so)
    print("\n[" + match + "] Layer '" + layer_name + "' Row '" + col_no + "'")
    print(f"Src '" + col_so + "' Dst '" + col_de + "' Action '" + col_ac + "' Description '" + col_co + "'")


##############################
# Global Methods
##############################
# OK
def print_start():
    """
    Description:
        Print start banner for display matched rules
    """
    print(f"{bcolors.BLUE}\n-----------------------[START]-----------------------{bcolors.RESET}")

# OK
def print_end():
    """
    Description:
        Print end banner for display matched rules
    """
    print(f"{bcolors.BLUE}\n------------------------[END]------------------------\n{bcolors.RESET}")

# OK
def msg_sys(message):
    """
    Description:
        Exec sys.exit() with specific message and RED color
    Input:
        message - (String) message to output
    """
    sys.exit(f"{bcolors.RED}" + message + f"{bcolors.RESET}")

# OK
def msg_wrn(message):
    """
    Description:
        Print message with specific message in YELLOW color
    Input:
        message - (String) message to output
    """
    print(f"{bcolors.YELLOW}" + message + f"{bcolors.RESET}")

# OK
if __name__ == "__main__":
    """"""
    main()
