from scapy.all import *
import subprocess



"""
    Network Host Scanning
"""

def get_network_hosts(target_hosts) :

    active_hosts = []

    paquets_for_each_host = [p for p in IP(dst=[target_hosts])/ICMP()]
    
    for paquet in paquets_for_each_host:

        answer = sr1( paquet , timeout=1)
        try :
            active_hosts.append(answer[IP].src)
        except : 
            pass

        print("\n\n+++++")
    
    return active_hosts


"""
    Host Query
"""

def getting_stacks_by_host_snmp(active_hosts,community):

    hosts_report = []

    for host in active_hosts:
        
        stacks = []

        commande_output = subprocess.getstatusoutput("snmpwalk -v1 -c %s %s 1.3.6.1.2.1.25.6.3.1.2" %(community, host))
        
        if commande_output[0] == 0:
            
            mibs = commande_output[1].split('\n')
            
            for mib in mibs :

                stack = mib.split('"')[1]

                versions_info = stack.split("-")[-2:]
                stack_names =  stack.split("-")[:-2]
                

                try :
                        
                    if versions_info[0][0].isdigit() : 
                      
                        stacks.append({
                            "name": "-".join(stack_names) , 
                            "version": "-".join(versions_info)
                        })
                        
                        
                    elif versions_info[1][0].isdigit():

                        stacks.append({
                            "name": "-".join(stack_names,versions_info[0]) , 
                            "version": versions_info[1]
                        })
                    
                    else:

                        stacks.append({
                            "name": stack , 
                            "version": stack
                        })

                except: 
                    pass

        commande_output = subprocess.getstatusoutput("snmpwalk -v1 -c %s %s .1.3.6.1.2.1.1.1.0" %(community, host))
        os_info = commande_output[1].split('"')[1]

        hosts_report.append({
            "os":os_info,
            "ipv4":host,
            "packages":stacks
        })       

    return hosts_report
	

