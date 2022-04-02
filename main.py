import re
import paramiko

#exucte commande on the ssh server and get the output
def cmd_exec(ssh,cmd) : 

    stdin, stdout, ssh_stderr = ssh.exec_command(cmd)
    out = stdout.read()
    stdin.flush()
    return out.decode('utf-8')


#get the os of the ssh server
def get_host_os(ssh) :

    output = cmd_exec(ssh,"hostnamectl")
    
    commande_output_lines = output.split('\n')
 
    for line in commande_output_lines : 
        if "system" in line.lower() :
            return line.split(':')[-1].lower().lstrip()

    return 0


#format pakage and their version in list
def format_pkg_version(packages,host_os) :

    pkg_versions = packages.split("\n")

    tab = []

    if "ubuntu" in host_os or "debian" in host_os or "centos" in host_os:

        for pkg_version in pkg_versions : 

            try :
                p_v = pkg_version.split('^^')
                
                if p_v[1][0].isdigit() :
                    tab.append({
                        "name": p_v[0],
                        "version":p_v[1]
                    })
            except :
                pass
            
    elif "alpine" in host_os :

        for pkg_version in pkg_versions :

            try:
            
                index_version = pkg_version.index('.')

                if pkg_version[index_version-1].isdigit() : 
                    tab.append({
                        "name": pkg_version[:index_version-3],
                        "version":pkg_version[index_version-2:]
                    })
                else :
                    tab.append({
                        "name": pkg_version[:index_version-1],
                        "version":pkg_version[index_version:]
                    })

            
            except :
                tab.append({
                        "name": pkg_version,
                        "version":pkg_version
                    })

    return tab


#get package of the host and save it in a file
def get_host_packages(ssh,cmd,host_os,file,container):

    target  = container if container is not None else host_os 

    output = cmd_exec(ssh,cmd)

    packages_versions = format_pkg_version(output,host_os)

    file.writelines( [
            
            "\n\t\"%s\" : {\n " % target ,
            "\"packages\" : %s"     %  packages_versions , 
            "\n\t},\t",
            
            ])

    print("list Package for %s successfull !!!\n\n" % target)
   

#get container name and images 
def get_container_name_and_images(ssh,cmd) :

    output = cmd_exec(ssh,cmd)

    containers_general_data = output.split('\n')
    containers_general_data.pop(0) #remove the las items because it is a space

    containers_info = {}

    for el in containers_general_data :
        if el != '' :
            tab = el.split(' ')
            containers_info[tab[-1]] = tab[3]
    
    return containers_info



#start audit a host in the network
def network_host_audit(host) :
    
        #establish connexion to the server 
        ssh = paramiko.SSHClient()

        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ssh.connect(hostname=host['ip'], username=host['username'], password=host['password'], compress = True,look_for_keys=False, allow_agent=False)

        #get the os of the server
        host_os = get_host_os(ssh)
        
        with open("report.json","w+") as file :

            #write the opening braket of the json object
            file.writelines( ["{"] )

            #check the os and get his the packages 

            if "alpine" in host_os : 
                get_host_packages(ssh,"apk info -vv | awk '{print $1}'",host_os,file,None)
            elif "ubuntu" in host_os :
                get_host_packages(ssh,"dpkg -l | awk '{print $2,$3}' OFS='^^'",host_os,file,None)
            elif "debian" in host_os :
                get_host_packages(ssh,"dpkg -l | awk '{print $2,$3}' OFS='^^'",host_os,file,None)
            elif "centos" in host_os :
                get_host_packages(ssh,"yum list installed | awk '{print $1,$2}' OFS='^^'",host_os,file,None)
            elif "rehl" in host_os :
                get_host_packages(ssh,"rpm -qa",host_os,file,None)


            #########
            ##
            ## start container inspection 
            ##
            ########

            containers_info = get_container_name_and_images(ssh,"docker ps")

            for container,image in containers_info.items() : 
                
                if "alpine" in image : 
                    get_host_packages(ssh,"docker exec "+container+" apk info -vv","alpine",file,container)
                elif "ubuntu" in image :
                    get_host_packages(ssh,"docker exec "+container+" dpkg -l","ubuntu",file,container)
                elif "debian" in image :
                    get_host_packages(ssh,"docker exec "+container+" dpkg -l","debian",file,container)
                elif "rehl" in image :
                    get_host_packages(ssh,"docker exec "+container+" rpm -qa","rehl",file,container)
                elif "centos" in image :
                    get_host_packages(ssh,"docker exec "+container+" yum list installed","centos",file,container)


            #write the closing braket of the json object
            file.writelines( ["}"] )
            
        file.close()


#format properly the content of the reported file to json syntax
def format_json_report_file() : 

    file_content = ""

    with open("report.json","r+") as file_in_read_mode :
        file_content = file_in_read_mode.read()
    file_in_read_mode.close()

    file_content = re.sub('\'','"',file_content)

    with open("report.json","w+") as file_in_write_mode :
        file_in_write_mode.write(file_content)
    file_in_write_mode.close()





host = {
    "ip":"127.0.0.1",
    "username":"root",
    "password":"root"
}

network_host_audit(host)

format_json_report_file()
