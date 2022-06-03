import sys 
import sys, platform, os
from pathlib import Path




def main() -> None:
    commande = ""
    try : 

        commande = sys.argv[1]
        
        if commande == "connect" :
            connect()
        else :
            raise ValueError() 
    except IndexError :
        print('usage: watchman-agent connect <client-id-key> <client-secret-key>')
        print('       watchman-agent connect snmp:<rocomunity> [network_addr|device_addr] <client-id-key> <client-secret-key>')

    except ValueError:
        print('usage: watchman-agent connect <client-id-key> <client-secret-key>')
        print('       watchman-agent connect snmp:<rocomunity> [network_addr|device_addr] <client-id-key> <client-secret-key>')


def connect() :

    snmp_mode = False
    snmp_arg = ""
    target_address = ""
    client_id = ""
    client_secret = ""

    try:
        
        if len(sys.argv) == 6:
            if "snmp" in sys.argv[2] :
                snmp_mode = True
                snmp_arg = sys.argv[2]
                target_address = sys.argv[3]
                client_id = sys.argv[4]
                client_secret = sys.argv[5]

        elif len(sys.argv) ==4:
            snmp_mode = False
            client_id = sys.argv[2]
            client_secret = sys.argv[3]

    except:
        print("\n❌️ Erreur d'execution ❌️")
        print("   Cause : Arguments missing for agent execution.\n")
        sys.exit(1)

    if platform.system() == 'Windows':
        env_path = str(Path(__file__).resolve().parent)+"\commands\dist\.env"
        if not snmp_mode :
            os.system(str(Path(__file__).resolve().parent)+"\commands\dist\main.exe %s %s %s" % (client_id,client_secret,env_path))
        else :
            os.system(str(Path(__file__).resolve().parent)+"\commands\dist\main.exe %s %s %s %s %s" % (snmp_arg , target_address , client_id,client_secret,env_path))

    else :


        env_path = str(Path(__file__).resolve().parent)+"/commands/dist/.env"

        if not snmp_mode :

            os.system(str(Path(__file__).resolve().parent)+"/commands/dist/main %s %s %s" % (client_id,client_secret,env_path))
        else:
            os.system("sudo "+str(Path(__file__).resolve().parent)+"/commands/dist/main %s %s %s %s %s" % (snmp_arg , target_address , client_id,client_secret,env_path))



