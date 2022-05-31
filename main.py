import subprocess
import re
import requests
import sys
import platform as pt
from snmp_fetching_stacks import *


def request_error() :
    print("\n❌️ Unable to join th server ❌️\n")
    print("   try one of the following solutions : \n")
    print("   👉️Try later")
    print("   👉️Verify your network connection")
    print("\nPlease contact +229 21604252 - 91911591 or support@watchman.bj if the problem persists.\n")
    sys.exit(1)


def get_container_name_and_images():

    containers_info = {}

    try:
        commande_output = subprocess.run(
            ["docker", "ps"], stdout=subprocess.PIPE)
        commande_output = commande_output.stdout.decode("utf-8")

        containers_general_data = commande_output.split('\n')
        containers_general_data.pop(0)

        for el in containers_general_data:
            if el != '':
                tab = el.split(' ')
                if "alpine" in tab[3] or "ubuntu" in tab[3] or "debian" in tab[3] or "rehl" in tab[3] or "centos" in tab[3]:
                    
                    containers_info[tab[-1]] = tab[3]
    except:
        pass

    return containers_info


def get_host_packages(commande, host_os, file, container):

    if host_os == 'Windows':

        commande_output = subprocess.check_output(commande, text=True)

        output_list = commande_output.split('\n')

        packages_versions = []

        for el in output_list:
            el = el.split()

            el = [i for i in el if i != '']  # purge space
            el = [i for i in el if not 'C:\\' in i]  # purge source

            try:

                if el[-1][0].isdigit():

                    p_v = {
                        "name": " ".join(el[:-1]),
                        "version": el[-1]
                    }

                elif el[-2][0].isdigit():
                    p_v = {
                        "name": " ".join(el[:-2]),
                        "version": el[-2]
                    }


                if p_v["name"] != "" :
                    packages_versions.append(p_v)
                    
            except:
                pass
        
    else:

        commande_output = subprocess.Popen(commande, stdout=subprocess.PIPE)

        packages_versions = format_pkg_version(commande_output, host_os)

    if container is None:

        file.writelines([

            "\"os\" : \"%s\" , " % host_os,
            "\"packages\" : %s ," % packages_versions,
            "\"containers\" : [ "

        ])

        
        print("\n\n❑ list Package for %s successfull !!!\n" % host_os)
    else:

        file.writelines([

            " { "
            " \"name\" : \"%s\" ," % container,
            " \"packages\" : %s " % packages_versions,
            " } "

        ])

        print(
            f" + list Package for {container} container in {host_os} successfull !!!\n")


def get_host_os():

    if pt.system() == 'Windows':
        return 'Windows'

    commande_output = subprocess.run(["hostnamectl"], stdout=subprocess.PIPE)
    commande_output_lines = commande_output.stdout.decode("utf-8").split('\n')

    for line in commande_output_lines:
        if "system" in line.lower():
            return line.split(':')[-1].lower().lstrip()


def format_pkg_version(commande1_output, host_os):

    if "ubuntu" in host_os or "debian" in host_os:
        output = subprocess.check_output(
            ["awk", "{print $2,$3}", "OFS=^^"], stdin=commande1_output.stdout)
    elif "alpine" in host_os:
        output = subprocess.check_output(
            ["awk", "{print $1}"], stdin=commande1_output.stdout)
    elif "centos" in host_os:
        output = subprocess.check_output(
            ["awk", "{print $1,$2}", "OFS=^^"], stdin=commande1_output.stdout)

    commande1_output.wait()

    pkg_versions = output.decode("utf-8").split("\n")

    tab = []

    if host_os.split(' ')[0] in ["ubuntu", "debian", "centos"]:

        for pkg_version in pkg_versions:

            try:
                p_v = pkg_version.split('^^')

                if p_v[1][0].isdigit():
                    tab.append({
                        "name": p_v[0],
                        "version": p_v[1]
                    })
            except:
                pass

    elif "alpine" in host_os:

        for pkg_version in pkg_versions:

            try:

                pkg_version = pkg_version.split(" - ")[0]
                p_v = pkg_version.split("-")

                name = "-".join(p_v[:-2])
                version = "-".join(p_v[-2:])

                tab.append({
                    "name": name,
                    "version": version
                })

            except:
                pass

    return tab


def network_host_audit(file):

    host_os = get_host_os()

    if host_os == 'Windows':

        get_host_packages(
            ["powershell", "-Command", "Get-Package"], host_os, file, None)

    else:

        if "alpine" in host_os:
            get_host_packages(["apk", "info", "-vv"], host_os, file, None)
        elif "ubuntu" in host_os:
            get_host_packages(["dpkg", "-l"], host_os, file, None)
        elif "debian" in host_os:
            get_host_packages(["dpkg", "-l"], host_os, file, None)
        elif "rehl" in host_os:
            get_host_packages(["rpm", "-qa"], host_os, file, None)
        elif "centos" in host_os:
            get_host_packages(["yum", "list", "installed"],
                              host_os, file, None)
        else: 
            print("😓️ Sorry, this type system is not supported yet;\n")
            sys.exit(1)
    #########
    ##
    # start container inspection
    ##
    ########

    containers_info = get_container_name_and_images()

    if len(containers_info):
        # get the key of the last container
        last_container = list(containers_info.keys())[-1]

    for container, image in containers_info.items():

        if "alpine" in image:
            get_host_packages(["docker", "exec", container,
                              "apk", "info", "-vv"], "alpine", file, container)
            # write a coma after the closed bracket only if it rest object to write
            if container != last_container:
               
                file.write(",")

        elif "ubuntu" in image:
            get_host_packages(["docker", "exec", container,
                              "dpkg", "-l"], "ubuntu", file, container)
            # write a coma after the closed bracket only if it rest object to write
            if container != last_container:
                file.write(",")

        elif "debian" in image:
            get_host_packages(["docker", "exec", container,
                              "dpkg", "-l"], "debian", file, container)
            # write a coma after the closed bracket only if it rest object to write
            if container != last_container:
                file.write(",")

        elif "rehl" in image:
            get_host_packages(["docker", "exec", container,
                              "rpm", "-qa"], "rehl", file, container)
            # write a coma after the closed bracket only if it rest object to write
            if container != last_container:
                file.write(",")

        elif "centos" in image:
            get_host_packages(["docker", "exec", container, "yum",
                              "list", "installed"], "centos", file, container)
            # write a coma after the closed bracket only if it rest object to write
            if container != last_container:
                file.write(",")
        


# format properly the content of the reported file to json syntax
def format_json_report(client_id, client_secret):

    file_content = ""

    with open("__", "r+") as file_in_read_mode:
        file_content = file_in_read_mode.read()
    file_in_read_mode.close()

    file_content = re.sub('\'', '"', file_content)

    with open("__", "w+") as file_in_write_mode:
        file_in_write_mode.write("")
    file_in_write_mode.close()

    try:
        
        ans = requests.post(
            url='http://127.0.0.1:3000/api/agents/webhook/' , 
            headers={
                        "AGENT-ID":client_id,
                        "AGENT-SECRET":client_secret 
                    },
            data= {
                    "data": file_content
                }
            )

        if ans.status_code != 200:
            print("\n❌️ Execution error ❌️")
            print("   Detail : ", ans.json()["detail"])


    except:

        request_error()


def main():

    """
        Getting params give for the agent execution
    """

    try:
       
        if len(sys.argv) ==5 :
            if "snmp" in sys.argv[1] :
                snmp_mode = True
                snmp_arg = sys.argv[1]
                target_address = sys.argv[2]
                client_id = sys.argv[3]
                client_secret = sys.argv[4]
        elif len(sys.argv) ==3:
            snmp_mode = False
            client_id = sys.argv[1]
            client_secret = sys.argv[2]
    except:
        print("\n❌️ Execution error ❌️")
        print("   Detail : Arguments required for script execution.\n")
        sys.exit(1)


    """
        Authentication with the AGENT-ID and AGENT-SECRET
    """

    token = None 
    
    try:
        
        ans = requests.get('http://127.0.0.1:3000/api/agents/connect', headers={
           "AGENT-ID":client_id,
           "AGENT-SECRET":client_secret
        })

      
        if ans.status_code != 200:
            print("\n❌️ Authentication error  ❌️")
            print("   Detail : ", ans.json()["detail"])
           
        else :
            token = ans.json()["token"]

    except:
        request_error()
    
    if token is None :
        sys.exit(1)


    """
        Getting stacks from the target 
    """
    if not snmp_mode : 

        """
            By cmd execution
        """

        with open("__", "w+") as file:

            # write the opening braket of the json object
            file.writelines(["{"])

            file.writelines(["  \"%s\" : { " % pt.node(), ])

            network_host_audit(file)

            file.writelines([" ] } } "])

        file.close()

        format_json_report(client_id, client_secret)


    else :

        """
            By snmp mibs 
        """
        try : 
            community = snmp_arg.split(":")[1]
        except : 
            print("\n❌️ Execution error ❌️")
            print("   Detail : snmp community not specify.\n")
            sys.exit(1)

        hosts = get_network_hosts(target_address)
        
        report = getting_stacks_by_host_snmp(hosts,community)


        with open("__", "w+") as file:
            file.write("%s" % report)
        file.close()
        
        format_json_report(client_id, client_secret)

main()
