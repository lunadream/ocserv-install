#!/bin/bash
####################################################
#                                                  #
# This is a ocserv installation for CentOS 6       #
# Version: 20150826-001                            #
# Author: Yvonne Lu                                #
# Website: https://noname.space                    #
#                                                  #
####################################################

# Check for root
if [[ $(id -u) != "0" ]]; then
    printf "\e[42m\e[31mError: You must be root to run this install script.\e[0m\n"
    exit 1
fi

# Check for Centos or RHEL 6
if [[ $(grep "release 6." /etc/redhat-release 2>/dev/null | wc -l) -eq 0 ]]; then
    printf "\e[42m\e[31mError: Your OS is NOT CentOS 6 or RHEL 6.\e[0m\n"
    printf "\e[42m\e[31mThis install script is ONLY for CentOS 6 and RHEL 6.\e[0m\n"
    exit 1
fi

basepath=$(dirname $0)
cd ${basepath}

function ConfigEnvironmentVariable {
    #ocserv
    ocserv_version=0.10.4
    version=${1-${ocserv_version}}
    libtasn1_version=4.5
    # 
    # Max number of clients with same IP - default is 2
    maxsameclients=10
    # Maximum number of connections , the default is 16
    maxclients=1024
    # Certificates and key file server , placed in the same directory of the script
    # the permissions key file should be 600 or 400
    servercert=${2-server-cert.pem}
    serverkey=${3-server-key.pem}
    # Configuration directory , you can change the / etc / ocserv like
    confdir="/usr/local/etc/ocserv"

    # Installing System Components
    yum install -y -q net-tools bind-utils
    # Get the name of network interface cards
    ethlist=$(ifconfig | grep "Link encap" | cut -d " " -f1)
    eth=$(printf "${ethlist}\n" | head -n 1)
    if [[ $(printf "${ethlist}\n" | wc -l) -gt 2 ]]; then
        echo ======================================
        echo "Network Interface list:"
        printf "\e[33m${ethlist}\e[0m\n"
        echo ======================================
        echo "Which network interface you want to listen for ocserv?"
        printf "Default network interface is \e[33m${eth}\e[0m, let it blank to use default network interface: "
        read ethtmp
        if [[ -n "${ethtmp}" ]]; then
            eth=${ethtmp}
        fi
    fi

    # Port , the default is 10443
    port=443
    echo "Please input the port ocserv listen to."
    printf "Default port is \e[33m${port}\e[0m, let it blank to use default port: "
    read porttmp
    if [[ -n "${porttmp}" ]]; then
        port=${porttmp}
    fi

    # User name default user
    username=user
    echo "Please input ocserv user name:"
    printf "Default user name is \e[33m${username}\e[0m, let it blank to use default user name: "
    read usernametmp
    if [[ -n "${usernametmp}" ]]; then
        username=${usernametmp}
    fi

    #Random password
    randstr() {
        index=0
        str=""
        for i in {a..z}; do arr[index]=$i; index=$(expr ${index} + 1); done
        for i in {A..Z}; do arr[index]=$i; index=$(expr ${index} + 1); done
        for i in {0..9}; do arr[index]=$i; index=$(expr ${index} + 1); done
        for i in {1..10}; do str="$str${arr[$RANDOM%$index]}"; done
        echo ${str}
    }
    password=$(randstr)
    printf "Please input \e[33m${username}\e[0m's password:\n"
    printf "Default password is \e[33m${password}\e[0m, let it blank to use default password: "
    read passwordtmp
    if [[ -n "${passwordtmp}" ]]; then
        password=${passwordtmp}
    fi
}

function PrintEnvironmentVariable {
    # Print configuration parameters
    clear
    ipv4=$(ip -4 -f inet addr | grep "inet " | grep -v "lo:" | grep -v "127.0.0.1" | grep -o -P "\d+\.\d+\.\d+\.\d+\/\d+" | grep -o -P "\d+\.\d+\.\d+\.\d+")
    ipv6=$(ip -6 addr | grep "inet6" | grep -v "::1/128" | grep -o -P "([a-z\d]+:[a-z\d:]+\/\d+)" | grep -o -P "([a-z\d]+:[a-z\d:]+)")
    echo -e "IPv4:\t\t\e[34m$(echo ${ipv4})\e[0m"
    echo -e "IPv6:\t\t\e[34m$(echo ${ipv6})\e[0m"
    echo -e "Port:\t\t\e[34m${port}\e[0m"
    echo -e "Username:\t\e[34m${username}\e[0m"
    echo -e "Password:\t\e[34m${password}\e[0m"
    echo
    echo "Press any key to start install ocserv."

    get_char() {
        SAVEDSTTY=$(stty -g)
        stty -echo
        stty cbreak
        dd if=/dev/tty bs=1 count=1 2> /dev/null
        stty -raw
        stty echo
        stty ${SAVEDSTTY}
    }
    char=$(get_char)
    clear
}

function CompileOcserv {
    # Upgrading the system
    yum update -y -q
    yum install -y -q epel-release
    # Installation ocserv dependent components
    yum -y install autoconf automake gcc libtasn1-devel zlib zlib-devel trousers trousers-devel gmp-devel gmp xz texinfo libnl-devel libnl tcp_wrappers-libs tcp_wrappers-devel tcp_wrappers dbus dbus-devel ncurses-devel pam-devel readline-devel bison bison-devel flex expat-devel
    # Compile and install GNU Nettle
	wget http://ftp.gnu.org/gnu/nettle/nettle-2.7.1.tar.gz
	tar zxf nettle-2.7.1.tar.gz && cd nettle-2.7.1
	./configure --prefix=/usr && make
	make install &&chmod -v 755 /usr/lib/libhogweed.so.2.5 /usr/lib/libnettle.so.4.7 &&install -v -m755 -d /usr/share/doc/nettle-2.7.1 &&install -v -m644 nettle.html /usr/share/doc/nettle-2.7.1
	cd ..
	# Compile / install Unbound
	wget http://unbound.nlnetlabs.nl/downloads/unbound-latest.tar.gz
	tar zxf unbound-latest.tar.gz && cd unbound-*
	./configure && make && make install
	echo '/usr/local/lib' > /etc/ld.so.conf.d/local-libraries.conf && ldconfig
	mkdir -p /etc/unbound && unbound-anchor -a "/etc/unbound/root.key"
	cd ..
	# Compile /install gnutls
	wget ftp://ftp.gnutls.org/gcrypt/gnutls/v3.2/gnutls-3.2.15.tar.xz
	tar xvf gnutls-3.2.15.tar.xz
	cd gnutls-3.2.15
	export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
	./configure && make && make install
	cd ..
	# Compile / install libnl
	wget http://www.carisma.slowglass.com/~tgr/libnl/files/libnl-3.2.25.tar.gz
	tar xvf libnl-3.2.25.tar.gz
	cd libnl-3.2.25
	./configure && make && make install
	cd ..
	# Compile / install start-stop-dameon
	#wget http://ftp.de.debian.org/debian/pool/main/d/dpkg/dpkg_1.18.2.tar.xz
	#tar -xvf dpkg_1.18.2.tar.xz
	#cd dpkg-1.18.2
	#./configure
	#make
	#cd utils
	#make
	#cp -f start-stop-daemon /usr/bin/start-stop-daemon
	#cd ..
    # ocserv download, compile, install
    wget -t 0 -T 60 "ftp://ftp.infradead.org/pub/ocserv/ocserv-${version}.tar.xz"
    tar axf ocserv-${version}.tar.xz
    cd ocserv-${version}
    sed -i 's/#define MAX_CONFIG_ENTRIES.*/#define MAX_CONFIG_ENTRIES 200/g' src/vpn.h
    ./configure && make && make install
	
    # Copy the sample configuration file
    mkdir -p "${confdir}"
    cp "doc/sample.config" "${confdir}/ocserv.conf"
    wget https://gist.github.com/kevinzhow/9661623/raw/eb8bc8292f7e7b708b2baafe19ecd616155220a1/ocserv -O /etc/init.d/ocserv
	chmod 755 /etc/init.d/ocserv
    cd ${basepath}
}

function ConfigOcserv {
    # Detect whether there is a certificate and key files
    if [[ ! -f "${servercert}" ]] || [[ ! -f "${serverkey}" ]]; then
        #Create ca and server certificates（参考http://www.infradead.org/ocserv/manual.html#heading5）
        certtool --generate-privkey --outfile ca-key.pem

        cat << _EOF_ >ca.tmpl
cn = "LunaDream CA"
organization = "LunaDream Foundation"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
_EOF_

        certtool --generate-self-signed --load-privkey ca-key.pem \
        --template ca.tmpl --outfile ca-cert.pem
        certtool --generate-privkey --outfile ${serverkey}

        cat << _EOF_ >server.tmpl
cn = "LunaDream VPN"
o = "LunaDream Foundation"
serial = 2
expiration_days = 3650
signing_key
encryption_key #only if the generated key is an RSA one
tls_www_server
_EOF_

        certtool --generate-certificate --load-privkey ${serverkey} \
        --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem \
        --template server.tmpl --outfile ${servercert}
    fi

    # Copy the certificate to ocserv configuration directory
    cp "${servercert}" "${confdir}" && cp "${serverkey}" "${confdir}"

    # Add password to password file
    (echo "${password}"; sleep 1; echo "${password}") | ocpasswd -c "${confdir}/ocpasswd" ${username}

    sed -i "s#./sample.passwd#${confdir}/ocpasswd#g" "${confdir}/ocserv.conf"
    sed -i "s#server-cert = ../tests/server-cert.pem#server-cert = ${confdir}/${servercert}#g" "${confdir}/ocserv.conf"
    sed -i "s#server-key = ../tests/server-key.pem#server-key = ${confdir}/${serverkey}#g" "${confdir}/ocserv.conf"
    sed -i "s/max-same-clients = 2/max-same-clients = ${maxsameclients}/g" "${confdir}/ocserv.conf"
    sed -i "s/max-clients = 16/max-clients = ${maxclients}/g" "${confdir}/ocserv.conf"
    sed -i "s/tcp-port = 443/tcp-port = ${port}/g" "${confdir}/ocserv.conf"
    sed -i "s/udp-port = 443/udp-port = ${port}/g" "${confdir}/ocserv.conf"
    sed -i "s/default-domain = example.com/#default-domain = example.com/g" "${confdir}/ocserv.conf"
    sed -i "s/ipv4-network = 192.168.1.0/ipv4-network = 192.168.8.0/g" "${confdir}/ocserv.conf"
    sed -i "s/ipv4-netmask = 255.255.255.0/ipv4-netmask = 255.255.251.0/g" "${confdir}/ocserv.conf"
    sed -i "s/dns = 192.168.1.2/dns = 8.8.8.8\ndns = 8.8.4.4/g" "${confdir}/ocserv.conf"
    sed -i "s/run-as-group = daemon/run-as-group = nobody/g" "${confdir}/ocserv.conf"
    sed -i "s/cookie-timeout = 300/cookie-timeout = 86400/g" "${confdir}/ocserv.conf"
	sed -i "s/isolate-workers = true/isolate-workers = false/g" "${confdir}/ocserv.conf"
    sed -i 's$route = 192.168.1.0/255.255.255.0$#route = 192.168.1.0/255.255.255.0$g' "${confdir}/ocserv.conf"
    sed -i 's$route = 192.168.5.0/255.255.255.0$#route = 192.168.5.0/255.255.255.0$g' "${confdir}/ocserv.conf"



    # Modify ocserv Service
    #sed -i "s#^ExecStart=#ExecStartPre=/usr/bin/firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -s 192.168.8.0/21 -j ACCEPT\nExecStartPre=/usr/bin/firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 192.168.8.0/21 -o ${eth} -j MASQUERADE\nExecStart=#g" "/etc/init.d/ocserv"
    sed -i "s#/usr/sbin/ocserv#/usr/local/sbin/ocserv#g" "/etc/init.d/ocserv"
    sed -i "s#/etc/ocserv/ocserv.conf#$confdir/ocserv.conf#g" "/etc/init.d/ocserv"
}

function ConfigFirewall {

/sbin/service iptables status 1>/dev/null 2>&1

if [ $? -ne 0 ]; then
    iptables -I INPUT -p tcp --dport ${port} -j ACCEPT
    iptables -I INPUT -p udp --dport ${port} -j ACCEPT
    iptables -A FORWARD -s 192.168.8.0/21 -j ACCEPT
    iptables -t nat -A POSTROUTING -s 192.168.8.0/21 -o ${eth} -j MASQUERADE
    service iptables save
else
    printf "\e[33mWARNING!!! Either firewalld or iptables is NOT Running! \e[0m\n"
fi
}

function ConfigSystem {
    # Disable SELinx
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
    # Modify the system
    echo "Enable IP forward."
    sysctl -w net.ipv4.ip_forward=1
    echo net.ipv4.ip_forward = 1 >> "/etc/sysctl.conf"
    chkconfig ocserv --add
    echo "Enable ocserv service to start during bootup."
    chkservice ocserv on
    # Open ocserv Service
    service ocserv start0
    echo
}

function PrintResult {
    # Check firewall and ocserv
    clear
    printf "\e[36mChecking Firewall status...\e[0m\n"
    iptables -L -n | grep --color=auto -E "(${port}|192.168.8.0)"
    line=$(iptables -L -n | grep -c -E "(${port}|192.168.8.0)")
    if [[ ${line} -ge 2 ]]
    then
        printf "\e[34mFirewall is Fine! \e[0m\n"
    else
        printf "\e[33mWARNING!!! Firewall is Something Wrong! \e[0m\n"
    fi

    echo
    printf "\e[36mChenking ocserv service status...\e[0m\n"
    netstat -anp | grep ":${port}" | grep --color=auto -E "(${port}|ocserv|tcp|udp)"
    linetcp=$(netstat -anp | grep ":${port}" | grep ocserv | grep tcp | wc -l)
    lineudp=$(netstat -anp | grep ":${port}" | grep ocserv | grep udp | wc -l)
    if [[ ${linetcp} -ge 1 && ${lineudp} -ge 1 ]]
    then
        printf "\e[34mocserv service is Fine! \e[0m\n"
    else
        printf "\e[33mWARNING!!! ocserv service is NOT Running! \e[0m\n"
    fi

    # Print VPN parameters
    printf "
    if there are \e[33mNO WARNING\e[0m above, then you can connect to
    your ocserv VPN Server with the default user/password below:
    ======================================\n"
    echo -e "IPv4:\t\t\e[34m$(echo ${ipv4})\e[0m"
    echo -e "IPv6:\t\t\e[34m$(echo ${ipv6})\e[0m"
    echo -e "Port:\t\t\e[34m${port}\e[0m"
    echo -e "Username:\t\e[34m${username}\e[0m"
    echo -e "Password:\t\e[34m${password}\e[0m"
}

ConfigEnvironmentVariable
PrintEnvironmentVariable
CompileOcserv $@
ConfigOcserv
ConfigFirewall
ConfigSystem
PrintResult
exit 0
