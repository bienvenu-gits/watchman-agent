
import subprocess
import platform
import re
import os 
WINDOWS = "Windows"
LINUX = "Linux"


def get_container_name() :

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



def get_package(container,commande,file,_os) :

        commande_output = subprocess.Popen(commande,stdout=subprocess.PIPE)
        
        pkg_version =  get_pkg_version(commande_output,_os)
        
        
        file.writelines( [
            
            "\n\t'%s' : {\n " % container ,
                 "'packages' : %s"     %  pkg_version , 
                    "\n\t},\t",
            
            ])

        print("list Package for %s successfull !!!\n\n" % container)


def get_os() :

    if platform.system() == 'Windows' :
        return 'Windows'

    commande_output = subprocess.run(["hostnamectl"],stdout=subprocess.PIPE)
    commande_output_lines = commande_output.stdout.decode("utf-8").split('\n')

    for line in commande_output_lines : 
        if "system" in line.lower() :
            return line.split(':')[-1].lower()

    return 0

def get_pkg_version(commande1_output,_os) :

    if "ubuntu" in _os or "debian" in _os:
        output = subprocess.check_output( ["awk","{print $2,$3}","OFS=_"] , stdin=commande1_output.stdout )
    elif "alpine" in _os : 
        output = subprocess.check_output( ["awk","{print $1}"] , stdin=commande1_output.stdout )
    elif "centos" in _os :
        output = subprocess.check_output( ["awk","{print $1,$2}","OFS=/"] , stdin=commande1_output.stdout )

    commande1_output.wait()
    pkg_versions = output.decode("utf-8").split("\n")
    tab = []

    if "ubuntu" in _os or "debian" in _os:

        for pkg_version in pkg_versions : 

            try :
                p_v = pkg_version.split('_')
                
                if p_v[1][0].isdigit() :
                    tab.append({
                        "name": p_v[0],
                        "version":p_v[1]
                    })
            except :
                pass


    elif "alpine" in _os :

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

    elif "centos" in _os :

       for pkg_version in pkg_versions : 

            try :
                p_v = pkg_version.split('/')
                
                if p_v[1][0].isdigit() :
                    tab.append({
                        "name": p_v[0],
                        "version":p_v[1]
                    })
            except :
                pass

    return tab

def main() : 

    with open("report.txt","r+") as file :

        containers_info = get_container_name()

        for container,image in containers_info.items() : 

            if "alpine" in image : 
                get_package(container,["docker","exec",container,"apk","info","-vv"],file,"alpine")
            elif "ubuntu" in image :
                get_package(container,["docker","exec",container,"dpkg","-l"],file,"ubuntu")
            elif "debian" in image :
                get_package(container,["docker","exec",container,"dpkg","-l"],file,"debian")
            elif "rehl" in image :
                get_package(container,["docker","exec",container,"rpm","-qa"],file,"rehl")
            elif "centos" in image :
                get_package(container,["docker","exec",container,"yum","list","installed"],file,"centos")


        _os =  get_os()

        if _os == 'Windows' :

            get_package(_os,["Get-Package"],file)
            
        else : 
            
            if "alpine" in _os : 
                get_package(_os,["apk","info","-vv"],file,_os,)
            elif "ubuntu" in _os :
                get_package(_os,["dpkg","-l"],file,_os)
            elif "debian" in _os :
                get_package(_os,["dpkg","-l"],file,_os)
            elif "rehl" in _os :
                get_package(_os,["rpm","-qa"],file,_os)
            elif "centos" in _os :
                get_package(_os,["yum","list","installed"],file,_os)

    file.close()

  
main()

