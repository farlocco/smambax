#!/bin/bash
# Text color variables
black='\E[30;40m'
red='\E[31;40m'
green='\E[32;40m'
yellow='\E[33;40m'
blue='\E[34;40m'
magenta='\E[35;40m'
cyan='\E[36;40m'
white='\E[37;40m'
boldon='\033[1m'
boldoff='\033[0m'

# Default username, password, and domain
USER=""
PASS="-N"
DOMAIN=""
IPADDRESS=""
NBNAME=""
#tmp files
TFILE="/tmp/$(basename $0).$$.tmp"
UsersFILE="$TFILE.users"

# Required program(s)
req_progs=(smbclient nmap rpcclient nbtscan)
for p in ${req_progs[@]}; do
	hash "$p" 2>&- || \
	{ echo >&2 " Required program \"$p\" not installed."; exit 1; }
done

# Print header information
function header() {
	echo ""
	echo "####################################"
	echo "# SMamBax v0.2 - 2013.08.29        #"
	echo "# SMB enumeration                  #"
	echo "#                 Stefano Carli    #"
	echo "####################################"
	echo ""
}

# Clean-up and exit
function footer() {
	#remove temp files
	rm -rf $TFILE
	rm -rf $UsersFILE
	#exit
	echo ""
	exit 0
}

#check if ports 139 and 445 TCp are open
function check_ports() {
if nc -w 3 localhost 22 <<< ” &> /dev/null
then
echo ‘Port is open’
else
echo ‘Port is closed’
fi
}

# Convert hex rid values to decimal values
function convert_hex() {
	echo $(($1))
}

function use_nbtscan() {
	output=$(nbtscan -s ':' -r $1 | cut -d ':' -f 2)
	echo "NETBIOS name: " $output
}

function use_smbclient() {
	#Anonymous login
	#Options: -N > no password -g > grapable
	#& > silent output
	smbclient -N -g -L $1 &> $TFILE
	#get info
	echo "Domain: " $(cat $TFILE | grep 'Domain' | cut -d '[' -f 2) | cut -d ']' -f 1 #Domain info
	echo "OS " $(cat $TFILE | grep 'Domain' | cut -d '[' -f 3) | cut -d ']' -f 1 #Domain info
	echo "Server " $(cat $TFILE | grep 'Domain' | cut -d '[' -f 4) | cut -d ']' -f 1 - #Domain info
	#get shares
	shares=$(cat $TFILE | grep 'Disk' | cut -d '|' -f 2) #shares info
	if [ ! -z "$shares" ]; then	#any share?
		echo "-----------------------------"
		echo "Shares:"
		echo "-----------------------------"
		echo ""
		for share in $shares; do
			echo $share	#print share name
		done
		echo ""
		echo "[TIP] Try to connect to the above shares. Ex: smbclient \\\\\\\\$1\\\\$share"
		echo "-----------------------------"
	fi

	servers=$(cat $TFILE | grep 'Server|' | cut -d '|' -f 2) #neighborhood server
	if [ ! -z "$servers" ]; then	get Neighborhood SMB servers
		echo ""
		echo "-----------------------------"
		echo "Neighborhood SMB servers"
		echo "-----------------------------"
		echo ""
		for server in $servers; do
			echo $server	#print server name
		done
		echo ""
		echo "-----------------------------"
	fi

	domains=$(cat $TFILE | grep 'Workgroup|' | cut -d '|' -f 2) #neighborhood domains
	if [ ! -z "$domains" ]; then	#any server?
		echo ""
		echo "-----------------------------"
		echo "Neighborhood domains/workgroups"
		echo "-----------------------------"
		echo ""
		for domain in $domains; do
			echo $domain	#print domain name
		done
		echo ""
		echo "-----------------------------"
	fi
}

function use_rpcclient() {
	#get domain
	rpcclient -U='' $1 -N -c 'querydominfo' &> $TFILE
	DOM=$(cat $TFILE | tr -s '' '\t' | grep 'Domain:' | cut -d ':' -f 2)

	#get domain sid
	if [ ! -z "$DOM" ]; then
		DOMSID=$(rpcclient -U='' $1 -N -c "lookupdomain $DOM" | grep "SID:" | cut -d ":" -f 4)
		echo "Domain SID: $DOMSID"
		
	fi

	echo ""
	echo "-----------------------------"
	echo "Users and groups"
	echo "-----------------------------"
	echo ""
	cat $TFILE | grep 'Total' #Users/groups totals info

	echo "users"
	#search users with querydispinfo2
	rpcclient -U='' $1 -N -c 'querydispinfo2' &> $TFILE
	#Get RIDs
	rids=$(cat $TFILE | grep "Account" | cut -d ' ' -f 4)
	for rid in $rids; do
		#Get users for each RID
		user=$(cat $TFILE | grep "$rid" | cut -d ' ' -f 8 | cut -f 1)
		rid=$(convert_hex $rid)
		#write users and rids in a file
		echo "$user:$rid" &>> $UsersFILE
	done

	#usa un secondo comando per enumerare gli utenti, vediamo 
	#se riusciamo a trovare qualcosa in più
	rpcclient -U='' $1 -N -c 'enumdomusers' &> $TFILE
	
	rids=$(cat $TFILE | grep 'user' | cut -d '[' -f 3 | cut -d ']' -f 1)
	for rid in $rids; do
		dec_rid=$(convert_hex $rid)
		#controlla se il rid è già presente nel file degli utenti
		if ! grep --quiet "$dec_rid" $UsersFILE; then
			user=$(cat $TFILE | grep "$rid" | cut -d '[' -f 2 | cut -d ']' -f 1)
			echo "$user:$dec_rid" &>> $UsersFILE
		fi
	done

	if [ ! -f $UsersFILE ]; then
		
		######try to find usernames and RIDs by guessing.
		######start with the user Administrator. 
		######If it's a windows box Administrator should exist and have a rid of 500
		#info for user Administrator
		user=$(rpcclient -U='' $1 -N -c 'lookupnames Administrator')
		if [ ! -z "$user" ]; then
			username=$(echo $user | grep 'User' | cut -d ' ' -f 1)
			sid=$(echo $user | grep 'User' | cut -d ' ' -f 2)
			rid=$(echo $sid | cut -f8 -d-)
			DOM=$(echo $sid | sed 's/.\{4\}$//')
echo $DOM
			#start scanning
			MAX=600
			x=1
			while [ $rid -le $MAX ]
			do
				user=$(rpcclient -U='' $1 -N -c "lookupsids $DOM-$rid" | grep -v "*" | grep -v "failed" | cut -d '\' -f 2 | cut -d '(' -f 1
)
				rid=$(( $rid + 1 ))

				if [ ! -z "$user" ]; then
					username=$(echo $user | sed 's/.\{1\}$//')
					echo "$username:$rid" &>> $UsersFILE
				fi
				x=$x+1
			done
		fi
	fi
	
	if [ -f $UsersFILE ]; then
	echo "-------------------"
		echo "users found. Username:rid"
		echo "-------------------"
		cat $UsersFILE
	fi

	

	#enumerate builtin groups
	echo "builtin groups"
	rpcclient -U='' $1 -N -c 'enumalsgroups builtin'
	echo "domain groups"
	rpcclient -U='' $1 -N -c 'enumalsgroups domain'

	
}

header

if [[ -z $1 ]]; then
	#Show usage
	echo "usage $0 ip_address";
	echo "ex: $0 192.168.1.1";
else
	#Action
	IPADDRESS=$1
	echo "Ip address: " $IPADDRESS
	
	

	#nbtscan
	use_nbtscan $IPADDRESS

	#smbclient. Search for shared folder
	use_smbclient $IPADDRESS

	#rpcclient
	use_rpcclient $IPADDRESS

fi

footer