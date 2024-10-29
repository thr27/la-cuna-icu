#!/usr/bin/env bash
#set -x
echo $0
 
if [ -n "$windir" ]; then
	echo "ERROR not in windows... use salt.cmd"
	exit 1
fi
set -o pipefail

GIT_COMMIT_VERSION="DUMMY"

SALT_VERSION=3007.1

SCRIPT=`readlink -f -- $0`
SCRIPTPATH=`dirname $SCRIPT`
#CMDIPASS=$SCRIPTPATH/keepass/cmdipass
#CMDIPASS=$SCRIPTPATH/keepass/keypass
HOSTNAME=`hostname`
SSH_HOME=/root
CONFIG_BRANCH=master

# Time from Google
# date -s "$(curl -sD - google.com | grep '^Date:' | cut -d' ' -f3-6)Z"

function version_check() {
	local current_hash
    local remote_hash
    local url="https://thr27.github.io/la-cuna-icu/scripts/salt.sh"

    # Compute the SHA256 hash of the current script
    current_hash=$(sha256sum "$0" | awk '{ print $1 }')

    # Fetch the remote script and compute its SHA256 hash
    remote_hash=$(curl -s "$url" | sha256sum | awk '{ print $1 }')

    # Compare the hashes
    if [ "$current_hash" != "$remote_hash" ]; then
        echo "Notice: The script has been updated. Please update your local version. (local: $current_hash, remote: $remote_hash)"
		if ok "Update script?"; then
			self_upd_script=$(cat <<EOF
pushd .
cd
wget -O- https://thr27.github.io/la-cuna-icu/scripts/salt.sh > $SCRIPTPATH/salt.sh
popd
echo "salt.sh was updated ..."
EOF
)
			echo "$self_upd_script" > /tmp/upd_salt_sh.sh && chmod +x /tmp/upd_salt_sh.sh
			exec /tmp/upd_salt_sh.sh
		fi
    else
        echo "The script is up to date."
    fi
}
function version_check_old() {
	if [ "${GIT_COMMIT_VERSION}" != "DUMMY" ]; then
		
		REMOTE_GIT_VERSION=$(wget -O- -q https://thr27.github.io/la-cuna-icu/version.txt)
		if [ "${GIT_COMMIT_VERSION}" != "${REMOTE_GIT_VERSION}" ]; then
			if [ "${DO_INSTALL}" == "yes" ] || ok "This script version is outdated! Do you want to update? (local:${GIT_COMMIT_VERSION} != remote:${REMOTE_GIT_VERSION}) ... "
			then
				self_upd_script=$(cat <<EOF
pushd .			
cd
mkdir -p ts-salt-script/keepass && cd ts-salt-script
wget -O ./keepass/keepass https://thr27.github.io/la-cuna-icu/keepass && chmod +x ./keepass/keepass
wget -O- https://thr27.github.io/la-cuna-icu/salt.sh.enc |openssl enc -aes-256-cbc -md sha512 -d -k \$(./keepass/keepass -fn -k "https://thr27.github.io/la-cuna-icu/salt.sh") -pbkdf2 > salt.sh
popd
echo "salt.sh was updated ..."
EOF
)
				echo "$self_upd_script" > /tmp/upd_salt_sh.sh && chmod +x /tmp/upd_salt_sh.sh
				exec /tmp/upd_salt_sh.sh
				exit 1
			else
				echo Please update salt.sh
				exit 1
			fi
		fi
	fi
}

while getopts "yb:gaipd" o; do
	
    case "${o}" in
		y)
			echo "apply local state ..."
            DO_APPLY=yes
			echo "git update yes ..."
            DO_GIT=yes
            ;;
		b)
			echo "branch $OPTARG"
			CONFIG_BRANCH=$OPTARG
            ;;

        g)
			echo "skiping git update ..."
			SKIP_GIT_UPDATE=1
            ;;
        a)
			echo "apply local state ..."
            DO_APPLY=yes
            ;;
        p)  
			echo "remove old salt version ..."
            apt remove -y salt-minion salt-common
			rm /etc/apt/sources.list.d/salt.list
			rm -rf /srv/salt/*
			rm -rf /var/cache/salt
			rm -rf /tmp/my-server-config
			rm -rf /tmp/my-server-config.key

            ;;
        i)  
			echo "install or up/downgrade salt ..."
            DO_INSTALL=yes
            ;;
        d)  
			echo "Install git repro (on vagrant) ..."
            DO_GIT_VAGRANT=yes
            ;;
		h)
			echo "usage: $0 [-g] [-a] \n -g to skip git update \n -a to run apply "
			exit 0
    esac
done

function ok() {
	msg=$*
	while true
	do
		read -p "$msg (y/n) " ok	
		if [ "$ok" = "Y" ] || [ "$ok" = "y" ] || [ "$ok" = "j" ] || [ "$ok" = "J" ]
		then
			echo "Starting ...."
			return 0
		fi	
		if [ "$ok" = "n" ] || [ "$ok" = "N" ]
		then
			echo "Skipped ..."
			return 1
		fi
	done
}
function update_vagrant_time() {
	echo ${FUNCNAME[0]} 
	if [[ $(hostname -d) = 'prd.vagrant' ]]; then
		ND="$(wget -qSO- --max-redirect=0 --no-check-certificate --no-cache --no-cookies google.com 2>&1 | grep Date: | cut -d' ' -f5-8)Z"
		echo "Setting date from google.com to $ND"
		date -s "$ND"
	fi
	date
}
function is_root() {
	echo ${FUNCNAME[0]}
	if [ "$EUID" -ne 0 ]
		then echo "Please run as root"
  		exit -1
	fi
	
	update_vagrant_time
}
function install_salt() {
	echo ${FUNCNAME[0]}

	echo "## Need to upgrade Linux ..."
	apt update -y
	##apt install -y python3-mysqldb python3-pip
	apt install -y pkg-config
	apt upgrade -y

	if [ -f /etc/apt/sources.list.d/saltstack.list ]; then
		mv /etc/apt/sources.list.d/saltstack.list /etc/apt/sources.list.d/saltstack.list.`date +%y%m%d_%H%M%S`.save
	fi
	if [ -f /etc/apt/sources.list.d/salt.list ]; then
		mv /etc/apt/sources.list.d/salt.list /etc/apt/sources.list.d/salt.list.`date +%y%m%d_%H%M%S`.save
	fi
	mkdir -p /etc/apt/keyrings
	curl -fsSL -o /etc/apt/keyrings/salt-archive-keyring-2023.gpg https://repo.saltproject.io/salt/py3/ubuntu/20.04/amd64/SALT-PROJECT-GPG-PUBKEY-2023.gpg
	echo "deb [signed-by=/etc/apt/keyrings/salt-archive-keyring-2023.gpg arch=amd64] https://repo.saltproject.io/salt/py3/ubuntu/20.04/amd64/latest focal main" | tee /etc/apt/sources.list.d/salt.list

	curl -L https://bootstrap.saltstack.com -o /tmp/bootstrap_salt-X.sh 
	curl -L https://repo.saltproject.io/bootstrap/stable/bootstrap-salt.sh -o /tmp/bootstrap_salt.sh 

	bash /tmp/bootstrap_salt.sh -P -d -X onedir $SALT_VERSION 
	status=$?

	if [ $status -eq 0 ]; then
		/opt/saltstack/salt/bin/python3.10 -m pip install --upgrade pip
		
		salt-pip install PyMySQL
		salt-pip install mysqlclient
		salt-pip install docker

		systemctl stop salt-minion
		systemctl disable salt-minion
		# Altest python2.7 löschen, sonst fehler in docker-python
		#apt remove -y python2.7 python2.7-minimal libpython2.7 libpython2.7-minimal:amd64 libpython2.7-stdlib:amd64

		salt-call --local service.stop salt-minion
		salt-call --local service.disable salt-minion
	else
		echo "ERROR: salt-client not installed - Setup FAILED"
		exit 1
	fi
}
function bootstrap_salt() {
	echo ${FUNCNAME[0]}
	if ! type "salt-call" &> /dev/null; then
		
		install_salt
	fi
	
	#if ! salt-call --versions-report |grep -q  2019.2.0 
	if ! salt-call --versions-report |grep -q  $SALT_VERSION 
	then 
		echo "ERROR: wrong salt-client version. we need version $SALT_VERSION"
		salt-call --versions-report |grep "Salt:"
		
		if [ "${DO_INSTALL}" == "yes" ] || ok "Update/Downgrade salt-client ?"
		then
			if type "salt-call" &> /dev/null; then
				salt-call --local service.stop salt-minion ; salt-call --local service.disable salt-miniony
				apt purge -y salt-common salt-minion
				rm /etc/apt/sources.list.d/salt.list
				if [[ $(hostname -d) == 'prd.vagrant' ]]; then
					rm -rf /srv/salt/*
				fi
				rm -rf /var/cache/salt
			fi
			install_salt
		else
			exit 0
		fi
	fi
	
	salt-call --local service.stop salt-minion
	salt-call --local service.disable salt-minion
	
}
function setup_masterless_salt() {
	echo ${FUNCNAME[0]}
	
	#systemctl stop salt-minion
	
	mkdir -p /etc/salt.local/minion.d
	MYSQL_DEFAULT="mysql.default_file: /etc/mysql/conf.d/mysql-client.cnf"
	[ ! -f /etc/salt.local/minion ] && touch /etc/salt.local/minion
	
	if ! grep -q "no options" /etc/salt.local/minion; then
		echo "#no options" >> /etc/salt.local/minion
	fi
	if ! grep -q "use_superseded:" /etc/salt.local/minion; then
		echo "use_superseded:" >> /etc/salt.local/minion
		echo "  - module.run" >> /etc/salt.local/minion
	fi
	if ! grep -q "$MYSQL_DEFAULT" /etc/salt.local/minion; then
		echo "$MYSQL_DEFAULT" >> /etc/salt.local/minion
	fi
	SALT_DIRS=""
	while read x; do
		if [ ! -f $x/.windows ]; then
			if [ ! -f $x/.ignore ]; then
   				SALT_DIRS=$(cat <<DIRS
$SALT_DIRS
   - $x
DIRS
)
			fi
		fi
	done <<<$(find /srv/salt/ -maxdepth 1  -mindepth 1 -type d)
	
	echo $SALT_DIRS

	MASTERLESS_SALT=$(cat <<EOF


cachedir: /var/cache/salt.local/master

update_cachedir: False
minion_pillar_cache: False
yaml_utf8: True

file_client: local
file_ignore_regex:
  - '(^|/)\.svn($|/)'
  - '(^|/)\.git($|/)'

file_roots:
  base:
   - /srv/salt/my-server-config$SALT_DIRS

pillar_roots:
  base:
    - /srv/salt/my-server-config/pillar    

extmod_blacklist:
  modules:
    - clouds

disable_modules:
    - clouds
    
EOF
)
	echo "$MASTERLESS_SALT" > /etc/salt.local/minion.d/masterless.conf
	chmod 600 /etc/salt.local/*
	#systemctl start salt-minion
}
function setup_ssh() {
	echo ${FUNCNAME[0]}
	mkdir -p $SSH_HOME/.ssh
	PROXY_CMD=""
	
SSH_CONFIG=$(cat <<EOF
Host *
	PubkeyAcceptedKeyTypes +ssh-dss
    StrictHostKeyChecking accept-new

Host github.com
        User git
        Hostname github.com
        Port 22
        ${PROXY_CMD}

Host gitlab.com
        User git
        Hostname gitlab.com
        Port 22
        ${PROXY_CMD}
EOF
)
	echo "$SSH_CONFIG" > $SSH_HOME/.ssh/config

KNOWN_HOSTS=$(cat <<EOF		
|1|hwCB7v73vtL+sRUOf97fdInQ5uY=|1sm9yySawBDYBmdZYvh0QNmRDUg= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKXe7jkUe7fT+TjokqxK04bTgbYzIdsK5BKy7buijONH+dqWDUBOr7lvQi1pAJTPAl9zl1ThRQuoekJq1MlP0uI=
|1|ZJGAFOgeh847PCiEj6pMxAPum0A=|bN474ANTLgZtPD/96ddFWazlld0= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=
EOF
)
	echo "$KNOWN_HOSTS" >> $SSH_HOME/.ssh/known_hosts


}
function unlock_git() {
	echo ${FUNCNAME[0]}

	if [ ! -f /tmp/my-server-config.key ] ; then
		echo "Download decrypt key for secret files ..."
		load_secret_key_from_ssh_agent my-server-config
		if [ $? -ne 0 ]; then
			echo ERROR load_secret_key_from_keepass failed ...
			echo Please check your ssh-agent settings
			return 1
		fi
	fi

	if [ ! -d /tmp/my-server-config/.git ]; then
		echo "clone $CONFIG_BRANCH my-server-config to /tmp ..."
		git clone -b $CONFIG_BRANCH git@github.com:thr27/my-server-config.git /tmp/my-server-config
		
		if [ $? -ne 0 ]; then
			echo ERROR git clone failed ...
			return 1
		fi
	fi
	if [ ! -L /srv/salt/my-server-config ]; then
		ln -s /tmp/my-server-config /srv/salt/my-server-config
	fi

	pushd .
	cd /tmp/my-server-config
	if [ -f /tmp/my-server-config.key ]; then
		git-crypt unlock /tmp/my-server-config.key
		if [ $? -ne 0 ]; then
			echo ERROR git-unlock failed ...
			return 1
		fi
	fi
	popd
	return 0
}
function is_unlocked() {
	echo ${FUNCNAME[0]}

	[ -d /tmp/my-server-config/my-server-config ] && rm /tmp/my-server-config/my-server-config
	
	if grep -q "decryption OK" "/srv/salt/my-server-config/key.secret"; 
	then
		echo "Ok, my-server-config is unlocked ..."
		return 0
	else
		return 1
	fi
}
function setup_salt_dir() {
	echo ${FUNCNAME[0]}
	
	if ! type "git" &> /dev/null; then
		apt-get install -y git git-crypt
	fi
	if ! type "git-crypt" &> /dev/null; then
		apt-get install -y git-crypt
	fi
	
	if [ "${DO_GIT}x" == "x" ] && [ -z ${SKIP_GIT_UPDATE+x} ] && ok "Update git salt formulas (config=$CONFIG_BRANCH) ... ?" ; then
		DO_GIT=yes
	fi

	if [ "${DO_GIT}" == "yes" ] ; then
		echo "If git clone fails, pls. check deploy key settings in gitlab project ..."
		pushd .
		
		if [ ! -d /srv/salt ] ;	then
			echo "create /srv/salt dir"
			mkdir -p /srv/salt
		fi
		
		cd /srv/salt/

		dirs=(*/.git)
		if [ ${#dirs[@]} -gt 0 ]; then

			if [[ $(hostname -d) = 'prd.vagrant' && -z "$DO_GIT_VAGRANT" ]]; then
				echo Skipped on vagrant
			else
				echo "Update existing git folders ..."
				for i in */.git; do ( 

					echo git fetch/reset $BRANCH `dirname $i` ...; 
					if [ "$i" = '*/.git' ]; then
						return 1
					fi
					if [ -f $i/.git/config ]; then
						BRANCH=$(cat $i/.git/config|grep '\[branch ' |tr -d '[]"'|awk '{ print $2}')
					fi
					if [ $(dirname $i) = 'my-server-config' ]; then
						BRANCH=$CONFIG_BRANCH
					else
						BRANCH=master
					fi

					cd $i/..; 

					git fetch -fuv --progress origin $BRANCH:$BRANCH
					if [ $? -ne 0 ]; then
						echo ERROR git fetch failed ...
						return 1
					fi
					STATUS=$(git status -s|wc -l)
					if [[ $STATUS -gt 0  ||  $(git branch -l|grep '*'|awk '{ print $2 }') != $BRANCH ]]; then
						echo updating $BRANCH ...
						git checkout $BRANCH
						git reset --hard origin/$BRANCH; 

					else
						echo git is up-to-date
					fi
					cd; 
				); done
			fi
		fi
		if [[ -L "/srv/salt/my-server-config" && -d "/srv/salt/my-server-config" ]]
		then
			echo "/srv/salt/my-server-config is a symlink to a directory, ok."
		else
			if [[ $(hostname -d) = 'prd.vagrant' && -z "$DO_GIT_VAGRANT" ]]; then
				echo "Ignored on vagrant, test system"
				if [[ ! -L "/tmp/my-server-config" && ! -d "/tmp/my-server-config" ]]; then
					ln -s /srv/salt/my-server-config /tmp
				fi
			else
				if [[ -d "/srv/salt/my-server-config" ]]; then
					echo "Please remove /srv/salt/my-server-config, /srv/salt/my-server-config is not a link to /tmp//srv/salt/my-server-config"
					echo "For security reason, my-server-config is only kept temporarily on the server"
					return 1
				fi
			fi
		fi
		if [[ $(hostname -d) = 'prd.vagrant' && -z "$DO_GIT_VAGRANT" ]]; then
				echo Skipped on vagrant
		else
			unlock_git
			if [ $? -ne 0 ]; then
				echo ERROR unlock_git failed ...
				return 1
			fi
		fi
		if ! is_unlocked; then
			echo "Error, key is not valid or not available. Please check your keepass setup"
			echo "Please check your keepass setup"
			return 1
		fi

		for prj in tulip-base tulip-nomad-formula tulip-nagios-formula tulip-salt-formula-linux tulip-screen-formular tulip-unattendedupgrades-formular tulip-mysql-formula tulip-nfs_server-formula tulip-saltstack-postfix-formula tulip-ntp-formula
		do
			if [ ! -d /srv/salt/$prj ] ; then
				echo "clone $prj ..."
				git clone git@github.com:thr27/${prj}.git $prj
				if [ $? -ne 0 ]; then
					echo ERROR git clone failed ...
					return 1
				fi
			fi
		done

		popd
	fi
	return 0
}
function load_secret_key_from_ssh_agent() {
	echo ${FUNCNAME[0]}

	if ! type "ssh-add" &> /dev/null; then
		echo ERROR: ssh-add not installed
		return 1
	fi
	SSH_AGENT_COMMENT=$(basename ${PWD})
	if ! set |grep -q SSH_AUTH_SOCK 2>/dev/null; then
		echo ERROR: cannot connect to ssh-agent - ssh_agent_forwarding not active
		echo Please enable ssh-agent-forwarding and add ssh key with Key comment ${SSH_AGENT_COMMENT} ..
		echo We use ssh-agent to retrieve git-crypt key
		return 1
	else
		GIT_CRYPT_KEY=$(ssh-add -L |grep ${SSH_AGENT_COMMENT}|awk '{ print $4 }')

		if [ $? -ne 0 ]; then
			echo Cannot get key for "$SSH_AGENT_COMMENT", please setup key in keepass with $SSH_AGENT_COMMENT as comment on key
			echo Use git-crypt export-key key.txt && cat key.txt |xxd -ps -c 4096, and add 
			echo add the git-crypt key as a comment to the private key '$SSH_AGENT_COMMENT <hex dump of exported git-crypt key>' in key agent / ssh-add
			return 1
		else
			echo ${GIT_CRYPT_KEY} | xxd -ps -d > /tmp/$1.key
		fi
	fi
	return 0
}
#### MAIN
echo "### $0 git-version:${GIT_COMMIT_VERSION}"
is_root
version_check
setup_ssh
 
setup_salt_dir
if [ $? -ne 0 ]; then
	echo ERROR git clone failed ...
	exit 1
fi

bootstrap_salt
setup_masterless_salt

DATE=`date +%Y-%m-%d-%H%M`
LOG_FILE=${SCRIPTPATH}/install_${DATE}.log
LOG_FILE_TEST=${SCRIPTPATH}/install_test_${DATE}.log

if [ "${DO_APPLY}" == "yes" ] || ok "Apply local salt state ?"
then
	salt-call -c /etc/salt.local --local state.apply -l debug 2>&1|tee "${LOG_FILE}"
	echo $LOG_FILE
else
	if ok "Test local salt state ?"
	then
		#salt-call -c /etc/salt.local --local state.apply -l debug test=true 2>&1|tee "${LOG_FILE_TEST}"
		salt-call -c /etc/salt.local --local state.apply 2>&1|tee "${LOG_FILE_TEST}"
		echo $LOG_FILE_TEST
	else
		echo "run 'salt-call -c /etc/salt.local --local state.apply' to apply state ..."
		echo 'salt-call -c /etc/salt.local --local slsutil.renderer salt://.../....sls 2>&1|more'
		echo 'salt-call -c /etc/salt.local --local state.sls_id 'name of salt state' yourdir/your.sls 2>&1|more'
		# salt-call -c /etc/salt.local --local state.sls  nomad.uninstall nomad-remove-service -l debug
		# https://serverfault.com/questions/779950/saltstack-call-a-single-state-of-a-sls-file
		echo 'salt-call -c /etc/salt.local --local state.sls  <dir>.<sls file*ohne.sls*> <state-id> -l debug'
	fi
fi
