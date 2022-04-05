import subprocess
import platform
import re
import os 
import requests


WINDOWS = "Windows"
LINUX = "Linux"


def get_container_name_and_images() :

    commande_output = subprocess.run(["docker","ps"], stdout=subprocess.PIPE)
    commande_output_bites = commande_output.stdout

    containers_general_data = commande_output_bites.decode("utf-8").split('\n')
    containers_general_data.pop(0)

    containers_info = {}

    for el in containers_general_data :
        if el != '' :
            tab = el.split(' ')
            containers_info[tab[-1]] = tab[3]
    
    return containers_info



def get_host_packages(commande,host_os,file,container) :

        commande_output = subprocess.Popen(commande,stdout=subprocess.PIPE)
        
        packages_versions =  format_pkg_version(commande_output,host_os)
        
        if container is None :

            file.writelines( [
                
                "\"os\" : \"%s\" , " % host_os ,
                "\"packages\" : %s ,"     %  packages_versions ,
                "\"containers\" : [ "
            
                ])

            print("\n\n❑ list Package for %s successfull !!!\n" % host_os)
        else : 
            
            file.writelines([

                    " { "
                        " \"name\" : \"%s\" ," % container ,
                        " \"packages\" : %s " % packages_versions ,
                    " } "
                
            ])

            print(f" + list Package for {container} container in {host_os} successfull !!!\n" )

       


def get_host_os() :

    if platform.system() == 'Windows' :
        return 'Windows'

    commande_output = subprocess.run(["hostnamectl"],stdout=subprocess.PIPE)
    commande_output_lines = commande_output.stdout.decode("utf-8").split('\n')

    for line in commande_output_lines : 
        if "system" in line.lower() :
            return line.split(':')[-1].lower().lstrip()

    return 0



def format_pkg_version(commande1_output,host_os) :


    if "ubuntu" in host_os or "debian" in host_os:
        output = subprocess.check_output( ["awk","{print $2,$3}","OFS=^^"] , stdin=commande1_output.stdout )
    elif "alpine" in host_os : 
        output = subprocess.check_output( ["awk","{print $1}"] , stdin=commande1_output.stdout )
    elif "centos" in host_os :
        output = subprocess.check_output( ["awk","{print $1,$2}","OFS=^^"] , stdin=commande1_output.stdout )

    commande1_output.wait()

    pkg_versions = output.decode("utf-8").split("\n")
    print(pkg_versions)
    tab = []
    
    if host_os.split(' ')[0] in  ["ubuntu","debian" ,"centos"]:
        
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

                pkg_version = pkg_version.split(" - ")[0]
                p_v = pkg_version.split("-")
            
                
                name = "-".join(p_v[:-2])
                version = "-".join(p_v[-2:])

                print(name,version)

                tab.append({
                         "name":name,
                         "version":version
               })
                

            
            except :
               pass

    

    return tab



def network_host_audit() : 

        host_os =  get_host_os()

       
        if host_os == 'Windows' :

            get_host_packages(["Get-Package"],host_os,file,None)
            
        else : 
            
            if "alpine" in host_os : 
                get_host_packages(["apk","info","-vv"],host_os,file,None)
            elif "ubuntu" in host_os :
                get_host_packages(["dpkg","-l"],host_os,file,None)
            elif "debian" in host_os :
                get_host_packages(["dpkg","-l"],host_os,file,None)
            elif "rehl" in host_os :
                get_host_packages(["rpm","-qa"],host_os,file,None)
            elif "centos" in host_os :
                get_host_packages(["yum","list","installed"],host_os,file,None)



        #########
        ##
        ## start container inspection 
        ##
        ########


        containers_info = get_container_name_and_images()

        if len(containers_info) :
            last_container = list(containers_info.keys())[-1] #get the key of the last container 
    
        for container,image in containers_info.items() : 

            if "alpine" in image : 
                get_host_packages(["docker","exec",container,"apk","info","-vv"],"alpine",file,container)
            elif "ubuntu" in image :
                get_host_packages(["docker","exec",container,"dpkg","-l"],"ubuntu",file,container)
            elif "debian" in image :
                get_host_packages(["docker","exec",container,"dpkg","-l"],"debian",file,container)
            elif "rehl" in image :
                get_host_packages(["docker","exec",container,"rpm","-qa"],"rehl",file,container)
            elif "centos" in image :
                get_host_packages(["docker","exec",container,"yum","list","installed"],"centos",file,container)

            #write a coma after the closed bracket only if it rest object to write
            if container != last_container :
                file.write(",")
        
   
 
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



with open("report.json","w+") as file :

    #write the opening braket of the json object
    file.writelines( ["{"] )

    file.writelines(["  \"%s\" : { " % os.uname()[1] ,])

    network_host_audit()

    file.writelines([ " ] } } "])

file.close()


format_json_report_file()