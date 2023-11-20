Vagrant.configure("2") do |config|
  config.vm.define "ubuntu-agent" do |agent|
    agent.vm.box = "ubuntu/bionic64"
    agent.vm.network "private_network", type: "dhcp"
    # Configure and provision the Linux agent here
    agent.vm.provision "shell", inline: <<-SHELL
      # Installez le service SNMP (exemple pour Debian/Ubuntu)
      sudo apt-get update
      sudo apt-get install -y snmpd

      # Configurez le service SNMP
      sudo echo "rocommunity public" >> /etc/snmp/snmpd.conf  # Communauté SNMP en lecture seule
      sudo systemctl restart snmpd
    SHELL
  end
#   config.vm.define "alpine-agent" do |agent|
#     agent.vm.box = "alpine/alpine64"
#     agent.vm.network "private_network", type: "dhcp"
#     # Configure and provision the Linux agent here
#     agent.vm.provision "shell", inline: <<-SHELL
#         # Installation de Net-SNMP (le package SNMP pour Alpine)
#         apk update
#         apk add net-snmp
#
#         # Configuration de la communauté SNMP en lecture seule (personnalisez selon vos besoins)
#         echo 'rocommunity public' >> /etc/snmp/snmpd.conf
#
#         # Activer et démarrer le service SNMP
#         rc-update add snmpd
#         /etc/init.d/snmpd start
#
#         # Ouvrir le port UDP 161 dans le pare-feu
# #         /sbin/iptables -A INPUT -p udp --dport 161 -j ACCEPT
# #         /etc/init.d/iptables save
#
#         # Redémarrer le service SNMP pour appliquer les modifications
#         /etc/init.d/snmpd restart
#     SHELL
#   end
#   config.vm.define "debian-agent" do |agent|
#     agent.vm.box = "debian/buster64"
#     agent.vm.network "private_network", type: "dhcp"
#     # Configure and provision the Linux agent here
#     agent.vm.provision "shell", inline: <<-SHELL
#       # Installez le service SNMP (exemple pour Debian/Ubuntu)
#       sudo apt-get update
#       sudo apt-get install -y snmpd
#
#       # Configurez le service SNMP
#       sudo echo "rocommunity public" >> /etc/snmp/snmpd.conf  # Communauté SNMP en lecture seule
#       sudo systemctl restart snmpd
#     SHELL
#   end
  config.vm.define "windows10-agent" do |agent|
      agent.vm.box = "gusztavvargadr/windows-10"
      agent.vm.network "private_network", type: "dhcp"
#       agent.vm.boot_timeout = 600
      agent.vm.communicator = "winrm"
      agent.winrm.username = "vagrant"
      agent.winrm.password = "vagrant"
      agent.winrm.basic_auth_only = true

      # Provisioning script pour configurer SNMP
      agent.vm.provision "shell", inline: <<-SHELL
            # Installez le service SNMP
            Install-WindowsFeature SNMP-Service

            # Configurez le service SNMP
            $communityString = "public"  # Communauté SNMP en lecture seule (ajustez au besoin)
            Set-Service -Name SNMP -StartupType 'Automatic'
            Set-Service -Name SNMPTRAP -StartupType 'Automatic'
            Set-Service -Name 'SNMP Trap' -StartupType 'Automatic'
            Set-SNMPService -SecurityLevel 3 -AuthProtocol 0 -PrivProtocol 0 -AuthPassphrase 'authpass' -PrivPassphrase 'privpass' -EnableAuthenticationTraps $true
            Add-SNMPCommunity -Name $communityString -ReadPermission Everyone
            Restart-Service SNMP
            Restart-Service SNMPTRAP
            Restart-Service 'SNMP Trap'

            # Ouvrez le port UDP 161 dans le pare-feu
#             New-NetFirewallRule -Name SNMP -DisplayName "SNMP" -Enabled True -Direction Inbound -Protocol UDP -Action Allow -LocalPort 161

            # Affichez la configuration SNMP
            Get-SNMPService
        SHELL
      end
end
