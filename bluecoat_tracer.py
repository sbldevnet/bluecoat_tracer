#!/bin/python3

"""
How To
------
    1. Add API_URL and FILE_PATH variables to vars.py file
    2. Exec pip install -r requirements.txt
    2. Exec python3 bluecoat_tracer.py

Versions
--------
    Tested in vpmxml-info version = 631.

Limitations
-----------
    Only check UserAuthenticationPolicyTable & WebAccessPolicyTable layers
    Not check Threat Risk Level (TL) (Not available in API)
    Not check ip-address in "Proxy IP Address/Port" object
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
from tabulate import tabulate
# Import var file
from vars import *

# Disable HTTPS server certificate exception terminal output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define Colors
colormap = {
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "blue": "\033[1;36m",
    "reset": "\033[0m"
}

def red(text):
    """
    Description:
        Return text in red color.
    """
    return colormap["red"] + text + colormap["reset"]

def yellow(text):
    """
    Description:
        Return text in yellow color.
    """
    return colormap["yellow"] + text + colormap["reset"]

def green(text):
    """
    Description:
        Return text in green color.
    """
    return colormap["green"] + text + colormap["reset"]

def blue(text):
    """
    Description:
        Return text in blue color.
    """
    return colormap["blue"] + text + colormap["reset"]


# Check python version
if sys.version_info[0] < 3:
    sys.exit(red("Upgrade Python Version"))

# Set Log
if sys.version_info[1] < 9:
    logging.basicConfig(filename=LOG_FILE_NAME, level=logging.DEBUG, \
        format='%(asctime)s - %(levelname)s - %(message)s') # for python <3.9
else:
    logging.basicConfig(filename=LOG_FILE_NAME, encoding='utf-8', level=logging.DEBUG, \
        format='%(asctime)s - %(levelname)s - %(message)s') # add encoding in python >=3.9


# Init Banner
print()
print()
print(blue("#####################################"))
print(blue("##  Symantec ProxySG Utility Tool  ##"))
print(blue("#####################################"))
print()
print(green("https://github.com/sburgosl"))
print()


##############################
# Main menu
##############################
logging.debug("START SCRIPT")

def main():
    """
    Description:
        Main menu.
    """
    logging.debug("Exec: main()")

    print()
    print(blue("[GLOBAL VARIABLES]"))
    print("Auth method: " + AUTH_METHOD)
    print("Proxy Port: " + str(PROXY_PORT))
    print("Exclude layers: " + str(EXCLUDE_LAYERS))
    print()
    print(blue("[OPTIONS]"))
    print("[1]: Search source IP match")
    print("[2]: " + red("[WIP]") + "Search destination (IP/FQDN/URL)")
    print("[3]: " + yellow("[Testing]") + "Search source/destination")
    print("[4]: Get / Select authentication")
    print("[5]: Select proxy port")
    print("[6]: Download policy xml")
    print("[0]: Exit")
    print("Select Option: ", end="")

    try:
        option = int(input())
        switcher = {
            1: menu_search_source_ip,
            2: get_online_categories,
            3: search_complete,
            4: edit_auth,
            5: edit_proxy_port,
            6: menu_download_policy,
            0: sys.exit
        }
        switcher.get(option, main)()

    except ValueError as error:
        yellow("Not valid input")
        logging.warning("Not int on main() input: %s",error)
    except KeyboardInterrupt:
        sys.exit("")
    except Exception as error:
        logging.critical(error)
        sys.exit('Error')

    main()


##############################
# [1]: Search source IP match
##############################

def menu_search_source_ip():
    """
    Description:
        Dispalys the policy rules that match with a source IP.
    """
    logging.debug("Exec: menu_search_source_ip()")

    root = get_xml_root()
    try:
        print("\nEnter source IP: ", end="")
        input_src = ipaddress.ip_address(input())

        print_start()

        # Get all ipobjects that matches with source ip
        match_src_objects = get_xml_src_object_match(root, input_src)

        # Get comb-obj that contains match_ipbojects. This improves efficency
        match_comb_obj = get_xml_com_obj_match(root, match_src_objects)

        layers_enabled = get_xml_policy_layers(root)
        for layer in layers_enabled:
            if layer.attrib.get('layertype') == 'com.bluecoat.sgos.vpm.UserAuthenticationPolicyTable'\
            or layer.attrib.get('layertype') == 'com.bluecoat.sgos.vpm.WebAccessPolicyTable':
                match_array_src = get_rows_src_match(layer, match_src_objects, match_comb_obj)
                print_layer_row(match_array_src)

        yellow("INFO: Objects matched")
        print(match_src_objects)
        print(match_comb_obj)
        print_end()

    except ValueError as error:
        logging.warning("Input menu_search_source_ip() is not ipadress: %s",error)
        yellow("Input not valid")
        menu_search_source_ip()


##############################
# [2]: search_dest
##############################



##############################
# [3]: search_complete
##############################

def search_complete():
    """
    Description:
        Dispalys the policy rules that match with a source IP and destination.
    """
    logging.debug("Exec: search_complete()")

    if not ONLINE:
        yellow("Warning: Function limited with var ONLINE = False")
        yellow("Not check Blue Coat Categories")
        sys.exit(red("Offile mode Currently Work In Progress"))

    root = get_xml_root()
    try:
        print("\nEnter source IP: ", end="")
        input_src = ipaddress.ip_address(input())

        print("Enter destination in URL Format. Example '//192.168.1.1' or 'http://google.es:443/test.jpg': ", end="")
        input_dest = urlparse(input())

        if input_dest.netloc == '':
            yellow('[Error]: Destination is not in URL format')
            logging.warning("Input destination search_complete() is not URL: %s",input_dest)

        else:
            print_start()

            # Get all objects that matches with source ip
            match_src_objects = get_xml_src_object_match(root, input_src)

            # Get comb-obj that contains match_ipbojects. This improves efficency
            match_comb_obj = get_xml_com_obj_match(root, match_src_objects)

            # Get all objects that matches with destination
            match_dst_objects = get_xml_dst_object_match(root, input_dest)

            # Get comb-obj that contains match_ipbojects. This improves efficency
            match_comb_obj_dst = get_xml_com_obj_match(root, match_dst_objects)

            layers_enabled = get_xml_policy_layers(root)
            for layer in layers_enabled:
                if layer.attrib.get('layertype') == 'com.bluecoat.sgos.vpm.UserAuthenticationPolicyTable'\
                or layer.attrib.get('layertype') == 'com.bluecoat.sgos.vpm.WebAccessPolicyTable':
                    match_array_src = get_rows_src_match(layer, match_src_objects, match_comb_obj)
                    match_array_dst = get_rows_dst_match(match_array_src, match_dst_objects)
                    print_layer_row(match_array_dst)

            yellow("INFO: Objects matched")
            yellow("Src:")
            print(match_src_objects)
            print(match_comb_obj)
            yellow("Dst:")
            print(match_dst_objects)
            print(match_comb_obj_dst)

            print_end()

    except ValueError as error:
        logging.warning("Input search_complete() is not ipadress: %s",error)
        search_complete()


##############################
# [4]: edit_auth
##############################

def edit_auth():
    """
    Description:
        List and select authentication groups.
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
        logging.info("Change authentication method value to '%s'", AUTH_METHOD)

    except IndexError as error:
        logging.warning("Out of index on edit_auth() input: %s", error)


##############################
# [5]: edit_proxy_port
##############################

def edit_proxy_port():
    """
    Description:
        Edit proxy_port value. Default proxy_port value is defined in vars.py file.
    """
    logging.debug("Exec: edit_proxy_port()")

    try:
        print("Insert proxy port: ", end="")
        global PROXY_PORT
        PROXY_PORT = int(input())
        print()
        logging.info("Change proxy port value to '%s'",PROXY_PORT)

    except ValueError as error:
        logging.warning("Not int in edit_proxy_port() input: %s",error)


##############################
# [6]: menu_download_policy
##############################

def menu_download_policy():
    """
    Description:
        Get user and password.
        List and select policies.
        List and select versions.
        Download selected policy version.
    """
    logging.debug("Exec: menu_download_policy()")

    if not ONLINE:
        yellow("WARNING: Option not available with var ONLINE = False")
    else:
        # Ask User & Pass
        print("Enter User (Management Center): ", end="")
        user = input()
        print("Enter Pass: ", end="")
        password = getpass()
        print()
        
        # Get policies
        loop = True
        while loop:
            policies = get_proxy_policies(user,password)
            if policies == "error":
                return
            loop = False
        
        # Print policies and Ask uuid
        loop = True
        while loop:
            for policy in policies:
                print("Policy uuid: '" + policy['uuid'] + "' Name: '" + policy['name'] + "' Desc: '" + policy['description'] + "'")
            print("Enter Policy uuid: ", end="")
            policy_uuid = input()

            # Get Versions
            versions = get_proxy_policy_versions(user, password, policy_uuid)
            if versions == "error":
                return
            if not versions == "retry":
                loop = False

        # Print versions and ask version number
        loop = True
        while loop:
            for version in versions:
                print("Version: '" + version['revisionNumber'] + "' Date: '" + version['revisionDate'] + "' : '" + version['revisionDescription'] + "'")
            print("Enter Version: ", end="")
            revision = input()
            
            # Get policy
            policy_download = get_proxy_policy_download(user, password, policy_uuid, revision)
            if not policy_download == "retry":
                loop = False

        print(green("[OK]"))

def get_proxy_policies(user, password):
    """
    Description:
        List and select policy from Symantec Management Center using API
    Input:
        user             - (str) user of symantec management center
        password         - (str) password of symantec management center
    Output:
        policies         - (str) json array policies response or "error".
    """
    logging.debug("Exec: get_proxy_policies()")

    try:
        url = API_URL+"policies/"
        req = requests.get(url, verify=False, auth=(user, password))
        logging.info("HTTP Status code in get_proxy_policies() '%s'", req.status_code)

        if req.status_code == 200:
            return req.json()
        if req.status_code == 401:
            yellow("HTTP 401: Unauthorized")
        elif req.status_code == 403:
            yellow("HTTP 403: Forbidden")
        elif req.status_code == 404:
            yellow("HTTP 404: Not Found")
        else:
            logging.error("Status Code not handled in get_proxy_policies()")

    except ValueError as error:
        logging.error("Error in response in get_proxy_policies(): %s", error)
    except requests.exceptions.ConnectionError as error:
        logging.error("Connection error in get_proxy_policies(): %s", error)
    except Exception as error:
        logging.error("Error not handled in get_proxy_policies(): %s", error)

    yellow("Connection Error: see logs for more info")
    return "error"

def get_proxy_policy_versions(user, password, policy_uuid):
    """
    Description:
        List and select policy versions from Symantec Management Center using API.
    Input:
        user        - (str) user of symantec management center.
        password    - (str) password of symantec management center.
        policy_uuid - (str) uuid of selected policy.
    Output:
        versions    - (str List) json array versions response, or "error" / "retry".
    """
    logging.debug("Exec: get_proxy_policy_versions()")

    try:
        url = API_URL+"policies/"+policy_uuid+"/versions/"
        req = requests.get(url, verify=False, auth=(user, password))
        logging.info("HTTP Status code in get_proxy_policy_versions(): %s", req.status_code)

        if req.status_code == 200:
            return req.json()
        if req.status_code == 401:
            yellow("HTTP 401: Unauthorized")
        elif req.status_code == 403:
            yellow("HTTP 403: Forbidden")
        elif req.status_code == 404:
            yellow("HTTP 404: Not Found")
            return "retry"
        else:
            logging.error("Status Code not handled in get_proxy_policy_versions()")

    except ValueError as error:
        logging.error("Error in response in get_proxy_policy_versions(): %s", error)
    except requests.exceptions.ConnectionError as error:
        logging.error("Connection error in get_proxy_policy_versions(): %s", error)
    except Exception as error:
        logging.error("Error not handled in get_proxy_policy_versions(): %s", error)

    yellow("Connection Error: see logs for more info")
    return "error"

def get_proxy_policy_download(user, password, policy_uuid, revision):
    """
    Description:
        Download and save policy xml.
    Input:
        user        - (str) user of symantec management center.
        password    - (str) password of symantec management center.
        policy_uuid - (str) uuid of selected policy.
        revision    - (str) revisionNumber of selected policy version.
    Output:
        string      - (str) Empty if it is OK. "retry" to reselect version, "error" for exit.
    """
    logging.debug("Exec: get_proxy_policy_download()")

    try:
        url = API_URL+"policies/"+policy_uuid+"/content/"+revision
        req = requests.get(url, verify=False, auth=(user, password))
        logging.info("HTTP Status code in get_proxy_policy_download(): %s", req.status_code)

        if req.status_code == 200:
            data = req.json()
            content = data['content']['xml']
            file = open(FILE_PATH, 'w')
            file.write(content)
            file.close()
            return

        if req.status_code == 401:
            yellow("HTTP 401: Unauthorized")
        elif req.status_code == 403:
            yellow("HTTP 403: Forbidden")
        elif req.status_code == 404:
            yellow("HTTP 404: Not Found")
            return "retry"
        else:
            logging.error("Status Code not handled in get_proxy_policy_download()")

    except ValueError as error:
        logging.error("Error in response in get_proxy_policy_download(): %s", error)
    except requests.exceptions.ConnectionError as error:
        logging.error("Connection error in get_proxy_policy_download(): %s", error)
    except Exception as error:
        logging.error("Error not handled in get_proxy_policy_versions(): %s", error)

    yellow("Connection Error: see logs for more info")
    return "error"


##############################
# Proxy Node Methods
##############################

def get_online_categories(destination):
    """
    Description:
        Get user and password
        Get custom and Symantec predefined Categories from proxy node
    Input:
        destination - (str) destination input.
    Output:
        categories  - (str list) [policy, bluecoat] categories.
    """
    logging.debug("Exec: get_online_categories()")

    # Ask User & Pass
    print("Enter User (Proxy Node): ", end="")
    user = input()
    print("Enter Pass: ", end="")
    password = getpass()
    print()
    rtext = get_proxy_categories(user,password, destination)
    logging.info("HTTP Response: %s",rtext)
    if "Error" in str(rtext):
        logging.error("Error in response in get_online_categories(): %s",rtext)
        msg_sys(str(rtext))
    else:
        print()
        policy = rtext[0].rsplit(':',1)[1].strip()
        bluecoat = rtext[1].rsplit(':',1)[1].strip()
        categories = [policy, bluecoat]
        return categories

def get_proxy_categories(user, password, destination):
    """
    Description:
        Get custom and Symantec predefined Categories from proxy node.
    Input:
        user        - (str) user of symantec management center.
        password    - (str) password of symantec management center.
        destination - (str) destination input.
    Output:
        rtext       - (str) HTTP Response categories in text.

    """
    logging.debug("Exec: get_proxy_categories()")

    try:
        req = requests.get(NODE_URL+"ContentFilter/TestUrl/"+destination,\
            verify=False, auth=(user, password))
        logging.info("HTTP Status code in get_proxy_categories() + '%s'",req.status_code)

        if req.status_code == 200:
            rtext = req.text.strip().split('\n')
            return rtext
        if req.status_code == 401:
            sys.exit(red("Authentication Error"))
        elif req.status_code == 403:
            sys.exit(red("Forbidden"))
        else:
            logging.error("Status Code not handled in get_proxy_categories()")

    except ValueError as e:
        logging.error("Error in response in get_proxy_categories()" + str(e))
    except requests.exceptions.ConnectionError as e:
        logging.error("Connection error in get_proxy_categories(): " + str(e))
    except Exception as e:
        logging.error("Error not handled in get_proxy_categories(): " + str(e))

    sys.exit(red("Connection Error: see logs for more info"))


##############################
# XML Methods
##############################

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
        sys.exit(red("No such xml file: Edit variable FILE_PATH in vars.py file or download it with option [6]"))


def get_xml_object_type(object_search):
    """
    Return xml object type
    """

    # logging.debug("Exec: get_xml_object_type() for '" + object_search + "'")

    root = get_xml_root()
    object_type = root.find('conditionObjects/*[@name="'+ object_search +'"]').tag

    # logging.debug("Object '" + object_search + "' XML Type '" + object_type + "'")

    return object_type

def get_xml_src_object_match(root, input_src):
    """
    Description:
        Search match in source objects (ipobject, h-o, proxy, group).
    Input:
        root        - (XML Element) XML root.
        input_src   - (ipaddress)   source IP address.
    Output:
        match_src_objects - (str List) Name of XML objects that matches.
    """
    logging.debug("Exec: get_xml_src_object_match()")
    logging.debug("Source IP: %s",input_src)

    match_src_objects = []
    # ipobject
    for ipobject in root.findall('conditionObjects/ipobject'):
        if input_src in ipaddress.ip_network(ipobject.attrib.get('value'), False):
            ipobject_name = ipobject.attrib.get('name')
            ipobject_subnet = ipobject.attrib.get('value')
            match_src_objects.append(ipobject_name)
            logging.info("Object match. Name '%s'  Subnet '%s'", ipobject_name, ipobject_subnet)
    # h-o
    for h_o_object in root.findall('conditionObjects/h-o'):
        if input_src in ipaddress.ip_network(h_o_object.attrib.get('h'), False):
            h_o_object_name = h_o_object.attrib.get('name')
            h_o_object_host = h_o_object.attrib.get('h')
            match_src_objects.append(h_o_object_name)
            logging.info("Object match. Name '%s'  Host '%s'", h_o_object_name, h_o_object_host)
    # proxy
    for proxy_object in root.findall("conditionObjects/proxy[@port='"+str(PROXY_PORT)+"']"):
        proxy_name = proxy_object.attrib.get('name')
        match_src_objects.append(proxy_name)
        logging.info("Object match. Name '%s'  Port '%s'", proxy_name, PROXY_PORT)
    # group
    for group_object in root.findall("conditionObjects/group[@group-base='"+AUTH_METHOD+"']"):
        group_name = group_object.attrib.get('name')
        match_src_objects.append(group_name)
        logging.info("Object match. Name '%s'  Group-base '%s'", group_name, AUTH_METHOD)

    return match_src_objects

def get_xml_com_obj_match(root, match_src_objects):
    """
    Description:
        Search comb-obj that contains match_src_objects.
    Input:
        root                - (XML Element) XML root,
        match_src_objects   - (str List) XML ipobjects/h-o names that include input_src IP.
    Output:
        match_comb_obj      - (str List) XML comb_obj names that include some match_src_objects.
    """
    logging.debug("Exec: get_xml_com_obj_match()")

    comb_obj_match    = []
    # comb_obj_no_match = []
    comb_objs = root.findall('conditionObjects/comb-obj')
    for comb_obj in comb_objs:
        comb_obj_name = comb_obj.attrib.get('name')
        comb_obj_cl1  = comb_obj.attrib.get('n-1') # 'false' = select, 'true' = negate
        comb_obj_cl2  = comb_obj.attrib.get('n-2') # 'false' = select, 'true' = negate
        cl1_list      = comb_obj.findall('c-l-1')
        cl2_list      = comb_obj.findall('c-l-2')

        # cl1 false and cl2 false
        if comb_obj_cl1 == 'false' and comb_obj_cl2 == 'false':
            cl1_match = False
            cl2_match = False
            for cl1 in cl1_list:
                cl1_name = cl1.attrib.get('n')
                if cl1_name in match_src_objects or cl1_name in comb_obj_match:
                    cl1_match = True
                    break
            if cl1_match:
                if cl2_list == []:
                    comb_obj_match.append(comb_obj_name) # cl1 ok, cl2 empty
                    logging.info("Comb-obj match. Name '%s'  Contains '%s'",\
                        comb_obj_name, cl1_name)
                else:
                    for cl2 in cl2_list:
                        cl2_name = cl2.attrib.get('n')
                        if cl2_name in match_src_objects or cl2_name in comb_obj_match:
                            cl2_match = True
                            comb_obj_match.append(comb_obj_name) # cl1 ok, cl2 ok
                            logging.info("Comb-obj match. Name '%s'  Contains '%s' & '%s'",\
                                comb_obj_name, cl1_name, cl2_name)
                            break
            # if not cl1_match or not cl2_match:
            #     comb_obj_no_match.append(comb_obj_name) # cl1 ko

        # cl1 false and cl2 true
        elif comb_obj_cl1 == 'false' and comb_obj_cl2 == 'true':
            cl1_match = False
            cl2_match = False
            for cl1 in cl1_list:
                cl1_name = cl1.attrib.get('n')
                if cl1_name in match_src_objects or cl1_name in comb_obj_match:
                    cl1_match = True
                    break
            if cl1_match:
                if cl2_list == []:
                    comb_obj_match.append(comb_obj_name) # cl1 ok, !cl2 empty
                    logging.info("Comb-obj match. Name '%s'  Contains '%s'",\
                        comb_obj_name, cl1_name)
                else:
                    for cl2 in cl2_list:
                        cl2_name = cl2.attrib.get('n')
                        if cl2_name in match_src_objects or cl2_name in comb_obj_match:
                            cl2_match = True
                            # comb_obj_no_match.append(comb_obj_name) # cl1 ok, !cl2 ok
                            break
                    if not cl2_match:
                        comb_obj_match.append(comb_obj_name) # cl1 ok, !cl2 ko
                        logging.info("Comb-obj match. Name '%s'  Contains '%s' & '%s'",\
                            comb_obj_name, cl1_name, cl2_name)
            # if not cl1_match:
            #     comb_obj_no_match.append(comb_obj_name) # cl1 ko

        # cl1 true and cl2 false
        elif comb_obj_cl1 == 'true' and comb_obj_cl2 == 'false':
            cl1_match = False
            cl2_match = False
            for cl1 in cl1_list:
                cl1_name = cl1.attrib.get('n')
                if cl1_name in match_src_objects or cl1_name in comb_obj_match:
                    # comb_obj_no_match.append(comb_obj_name) # !cl1 ok
                    cl1_match = True
                    break
            if not cl1_match:
                if cl2_list == []:
                    comb_obj_match.append(comb_obj_name) # !cl1 ko && cl2 empty
                    logging.info("Comb-obj match. Name '%s'  Negate source ", comb_obj_name)
                else:
                    for cl2 in cl2_list:
                        cl2_name = cl2.attrib.get('n')
                        if cl2_name in match_src_objects or cl2_name in comb_obj_match:
                            cl2_match = True
                            comb_obj_match.append(comb_obj_name) # !cl1 ko, cl2 ok
                            logging.info("Comb-obj match. Name '%s'  Negate cl1, cl2 '%s'",\
                                comb_obj_name, cl2_name)
                            break
                    # if not cl2_match:
                    #     comb_obj_no_match.append(comb_obj_name) # !cl1 ko && cl2 ko

        # cl1 true and cl2 true
        else:
            cl1_match = False
            cl2_match = False
            for cl1 in cl1_list:
                cl1_name = cl1.attrib.get('n')
                if cl1_name in match_src_objects or cl1_name in comb_obj_match:
                    # comb_obj_no_match.append(comb_obj_name) # !cl1 ok
                    cl1_match = True
                    break
            if not cl1_match:
                if cl2_list == []:
                    comb_obj_match.append(comb_obj_name) # !cl1 ko && !cl2 empty
                    logging.info("Comb-obj match. Name '%s'  Negate source ", comb_obj_name)
                else:
                    for cl2 in cl2_list:
                        cl2_name = cl2.attrib.get('n')
                        if cl2_name in match_src_objects or cl2_name in comb_obj_match:
                            cl2_match = True
                            # comb_obj_no_match.append(comb_obj_name) # !cl1 ko, !cl2 ok
                            break
                    if not cl2_match:
                        comb_obj_match.append(comb_obj_name) # !cl1 ko, !cl2 ko
                        logging.info("Comb-obj match. Name '%s'  Negate cl1 '%s' & cl2 '%s'",\
                                comb_obj_name, cl1_name, cl2_name)

    return comb_obj_match

def get_xml_dst_object_match(root, destination):
    """
    Description:
        Search match in destination objects (ipobject, a-url, categorylist4).
    Input:
        root              - (XML Element) XML root.

    Output:
        match_dst_objects - (str List) Name of XML objects that matches.
    """
    logging.debug("Exec: get_xml_dst_object_match()")
    logging.debug("Destination: %s",destination)

    match_dst_objects = []

    # vpm categories
    if ONLINE:
        if destination.geturl().startswith("//"):
            categories = get_online_categories(destination.geturl().strip("//"))
        else:
            categories = get_online_categories(destination.geturl())
        categories_custom   = categories[0].rsplit('; ')
        categories_bluecoat = categories[1].rsplit('; ')
        logging.info("Object match. vpm-cat %s; %s",categories_custom,categories_bluecoat)
        if not categories_custom == ['none']:
            for category in categories_custom:
                match_dst_objects.append(category)
        if not categories_bluecoat == ['none']:
            for category in categories_bluecoat:
                match_dst_objects.append(category)
    else: #WIP
        # If online not search <node> (vpm cat)
        categories_custom = [] #WIP
        match_dst_objects.append(categories_custom)

    # categorylist4
    for category in root.findall('conditionObjects/categorylist4'):
        category_name = category.attrib.get('name')        
        for cat_i in category.findall('sel/i'):
            cat_i_name = cat_i.text.strip(' \n\t')
            if cat_i_name in match_dst_objects:
                match_dst_objects.append(category_name)
                logging.info("Object match. Name '%s' cat <i> '%s'", category_name, cat_i_name)
        for cat_ai in category.findall('sel/ai'):
            cat_ai_name = cat_ai.attrib.get('n')
            if cat_ai_name in match_dst_objects:
                match_dst_objects.append(category_name)
                logging.info("Object match. Name '%s' cat <ai> '%s'", category_name, cat_ai_name)

    # a-url
    for a_url_object in root.findall("conditionObjects/a-url"):
        a_url_object_name = a_url_object.attrib.get('name')
        xml_h = a_url_object.attrib.get('h')
        xml_p = a_url_object.attrib.get('p')
        xml_d = a_url_object.attrib.get('d')

        if not xml_h == None:
            xml_h_t = a_url_object.attrib.get('h-t')
            if xml_h_t == 'exact-phrase':
                if not destination.hostname == xml_h:
                    continue
            elif xml_h_t == 'at-end':
                if not destination.hostname.endswith(xml_h):
                    continue
            elif xml_h_t == 'at-beginning':
                if not destination.hostname.startswith(xml_h):
                    continue
            elif xml_h_t == 'regex':
                if not re.match(xml_h, destination.hostname):
                    continue
            elif xml_h_t == 'contains':
                if not xml_h in destination.hostname:
                    continue
            else:
                logging.warning("a-url '%s' host condition (h-t in xml) not implemented in get_a_url_match()",xml_h_t)

        if not xml_p == None:
            xml_p_t = a_url_object.attrib.get('p-t')
            if xml_p_t == 'exact-phrase':
                if destination.path == xml_p:
                    match_dst_objects.append(a_url_object_name)
                    logging.info("Object match. Name '%s'  ", a_url_object_name)
                continue
            elif xml_p_t == 'at-end':
                if destination.path.endswith(xml_p):
                    match_dst_objects.append(a_url_object_name)
                    logging.info("Object match. Name '%s'  ", a_url_object_name)
                continue
            elif xml_p_t == 'at-beginning':
                if destination.path.startswith(xml_p):
                    match_dst_objects.append(a_url_object_name)
                    logging.info("Object match. Name '%s'  ", a_url_object_name)
                continue
            elif xml_p_t == 'regex':
                if bool(re.match(xml_p, destination.path)):
                    match_dst_objects.append(a_url_object_name)
                    logging.info("Object match. Name '%s'  ", a_url_object_name)
                continue
            elif xml_p_t== 'contains':
                if xml_p in destination.path:
                    match_dst_objects.append(a_url_object_name)
                    logging.info("Object match. Name '%s'  ", a_url_object_name)
                continue
            else:
                logging.warning("a-url '%s' path condition (p-t in xml) not implemented in get_xml_dst_object_match()",xml_p_t)
                continue

        # Simple match
        if not xml_d == None:
            if xml_d in destination.hostname:
                match_dst_objects.append(a_url_object_name)
                logging.info("Object match. Name '%s'  ", a_url_object_name)
            continue

        # Advanced match without xml_p
        else:
            match_dst_objects.append(a_url_object_name)
            logging.info("Object match. Name '%s'  ", a_url_object_name)

    # ipobject
    try:
        dest_ip = ipaddress.ip_address(destination.netloc)
        for ipobject in root.findall('conditionObjects/ipobject'):
            if dest_ip in ipaddress.ip_network(ipobject.attrib.get('value'), False):
                ipobject_name = ipobject.attrib.get('name')
                ipobject_subnet = ipobject.attrib.get('value')
                match_dst_objects.append(ipobject_name)
                logging.info("Object match. Name '%s'  Subnet '%s'", ipobject_name, ipobject_subnet)
    except ValueError as e:
        logging.debug("Input get_xml_dst_object_match() is not ipadress:" + str(e))

    return match_dst_objects

def get_auth_obj_match(auth_obj_name):
    """
    Check if xml auth-obj match with selected AUTH_METHOD (group in xml)
    Return boolean
    """
    logging.debug("Exec: get_auth_obj_match(%s)", auth_obj_name)

    root = get_xml_root()
    realm_search = root.find("conditionObjects/auth-obj[@name='" + auth_obj_name + "']").attrib.get('r-n')

    if AUTH_METHOD == '':
        return False

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

def get_xml_policy_layers(root):
    """
    Description:
        Get all layers enabled and not exclued in var exclude_layers.
    Input:
        root            - (XML Element) XML root
    Output:
        layers_enabled  - (XML Element List) Policy layers enabled
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

def evaluate_action(row):
    """
    Description:
        Return if action permit (True) or deny (False) traffic.
    Input:
        row - (XML Element) row with match.
    Output:
        Boolean / None
    """
    col_ac = row.find('colItem[@id="ac"]').attrib.get('name')

    # Evaluate action
    allow_actions   = ["Do Not Authenticate", "Allow"]
    deny_action     = ["Force Deny (Content Filter)", "Force Deny"]

    if col_ac in allow_actions:
        return True
    if col_ac in deny_action:
        return False

    dst_object_type = get_xml_object_type(col_ac)
    if dst_object_type == 'auth-obj':
        return get_auth_obj_match(col_ac)
    if dst_object_type == 'adm-auth-obj':
        if get_adm_auth_obj_match(col_ac):
            return True
        else:
            return False
    if dst_object_type == 'acc-log-fac':
        return None
    if dst_object_type == 'dny-exc':
        return None
    if dst_object_type == 'effective-threat-risk-lvl':
        return None
    else:
        yellow("Warning: Action not evaluated. See logs for more information")
        logging.warning("Object type '%s' not parsing in evaluate_action()", dst_object_type)

def get_rows_src_match(layer, match_src_objects, match_comb_obj):
    """
    Description:
        Check if src match in layers.
    Input:
        layer               - (XML Element) Layer to inspect.
        match_src_objects   - (str List)    XML objects Name that matches with input.
        match_comb_obj      - (str List)    XML comb-obj Name that matches with match_src_objects.
    Output:
        match_array_src     - ([] List)     [layer (XML Element), row (XML Element), action (bool)]
    """
    logging.debug("Exec: get_rows_src_match()")

    # Init array
    match_array_src = []

    # Check guard #WIP
    # guard = layer.find('guard')
    # if not guard == None:
    #     if not row.attrib.get('enabled') == 'false':

    # Get rows enabled in layer
    for row in layer.findall('rowItem'):
        if not row.attrib.get('enabled') == 'false':
            row_src = row.find('colItem[@id="so"]').attrib.get('name')

            # Check source match
            if row_src == 'Any' or row_src in match_src_objects or row_src in match_comb_obj:
                action = evaluate_action(row)
                match_array_src.append([layer, row, action])
            else:
                object_type = get_xml_object_type(row_src)
                if not object_type == 'comb-obj' and not object_type == 'proxy'\
                    and not object_type == 'group' and not object_type == 'ipobject':
                    yellow("Warning: Object not evaluated. See logs for more information")
                    logging.warning("Object type '%s' not parsing in get_rows_src_match(%s)", object_type, row_src)

    return match_array_src

def get_rows_dst_match(match_array_src, match_dst_objects):
    """
    Description:
        Check if dst match in layers.
    Input:
        match_array_src     - ([] List)     [layer (XML Element), row (XML Element), action (bool)]
        match_src_objects   - (str List)    XML objects Name that matches with input.
    Output:
        match_array_dst     - ([] List)     [layer (XML Element), row (XML Element), action (bool)]
    """
    logging.debug("Exec: get_rows_dst_match()")

    match_array_dst = []

    for match in match_array_src:
        layer  = match[0]
        row    = match[1]
        action = match[2]
        row_dst = row.find('colItem[@id="de"]').attrib.get('name')
        # print(row_dst) #DELETEME
        if row_dst == 'Any' or row_dst in match_dst_objects:
            match_array_dst.append([layer, row, action])
        else:
            object_type = get_xml_object_type(row_dst)
            # Bypass threat-risk and svr-cert objects
            if object_type == 'threat-risk' or object_type == 'svr-cert':
                match_array_dst.append([layer, row, action])
            elif not object_type == 'node' and not object_type == 'a-url'\
            and not object_type == 'categorylist4'and not object_type == 'ipobject'\
            and not object_type == 'comb-obj':
                yellow("Warning: Object not evaluated. See logs for more information")
                logging.warning("Object type '%s' not parsing in get_rows_dst_match(%s)", object_type, row_dst)

    return match_array_dst

def print_layer_row(match_array):
    """
    Description:
        Print match layers in table format
    Input:
        match_array - (List) [layer, row, action]
    """
    logging.debug("Exec print_layer_row()")

    # Define static print values
    headers         = ["", "Layer", "Row", "Src", "Dst", "Action", "Description"]
    action_allow    = green("✓")
    action_deny     = red("X")
    action_unknown  = yellow("?")

    # Init print array
    print_array = []
    for match in match_array:
        # Get layer and row data
        layer_name  = match[0].find('name').text.strip(' \n\t')
        col_no      = match[1].find('colItem[@id="no"]').attrib.get('value')
        col_so      = match[1].find('colItem[@id="so"]').attrib.get('name')
        col_de      = match[1].find('colItem[@id="de"]').attrib.get('name')
        col_ac      = match[1].find('colItem[@id="ac"]').attrib.get('name')
        col_co      = match[1].find('colItem[@id="co"]').attrib.get('name')

        # Set print action
        if match[2]:
            action = action_allow
        elif match[2] == False:
            action = action_deny
        else:
            action = action_unknown

        # Generate array for tabulate output
        print_array.append([action,layer_name,col_no,col_so,col_de,col_ac,col_co])

    # Print
    print(tabulate(print_array, headers))
    print()


##############################
# Global Methods
##############################

def print_start():
    """
    Description:
        Print start banner for display matched rules.
    """
    print(blue("\n-----------------------[START]-----------------------"))

def print_end():
    """
    Description:
        Print end banner for display matched rules.
    """
    print(blue("\n------------------------[END]------------------------\n"))

def msg_sys(message):
    """
    Description:
        Exec sys.exit() with specific message and RED color.
    Input:
        message - (String) message to output.
    """
    sys.exit(red(message))

def msg_wrn(message):
    """
    Description:
        Print message with specific message in YELLOW color.
    Input:
        message - (String) message to output.
    """
    print(yellow(message))

if __name__ == "__main__":
    """"""
    main()
