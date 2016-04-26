Ocserv install script for CentOS & RHEL 7
=======================================
This is a key ocserv in CentOS and RHEL 7 7 installation scripts can be deployed ocserv minimizing installation environment CentOS and RHEL 7

* Support automatically determining the firewall - make sure either firewalld or iptables is active
* The default user name using password authentication, this installation script compiled ocserv also supports pam authentication, only you need to modify the configuration files;
* The default configuration file in /usr/local/etc/ocserv/ directory, change the script's own parameters;
* When you install will prompt you to enter the port, user name, password and other information, can also directly enter the default value, the password is randomly generated;
* The installation script will close SELINUX;
* Since Router table, only the IP routing table will go VPN, if you need to add routing table to add their own support for up to 200;
If you have a certification authority certificate, the certificate can be placed under the same directory script, make sure the file name and the script matches the installation script will use your certificate, the certificate does not prompt an error when the client is connected;
Modify the configuration file for each account to allow 10 connections, the global 1024 connection, modify the script in front of the variable. 1024 connected approximately 2048 IP, so IP virtual interface configured with eight C segment.
The installation script is divided into several large pieces, if there is an error in the middle, can comment section and then re-execute the script, ConfigEnvironmentVariable as necessary, will be used later in the script variables here

* ConfigEnvironmentVariable // configuration environment variable
* PrintEnvironmentVariable // print environment variables
* CompileOcserv $ @ // download and compile ocserv
* ConfigOcserv // configuration ocserv, including modification ocserv.conf, configuration ocserv.service
* ConfigFirewall // configure the firewall, the firewall will automatically determine the iptables or firewalld
* ConfigSystem // configuration system
* PrintResult // print the final results of the installation and VPN accounts, etc.
