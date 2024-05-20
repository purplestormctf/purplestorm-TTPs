########### General CTF Aliases #############
alias dockershell="sudo docker run --rm -i -t --entrypoint=/bin/bash"
alias dockershellsh="sudo docker run --rm -i -t --entrypoint=/bin/sh"
alias ntlm.pw="function _ntlm(){ curl https://ntlm.pw/$1; }; _ntlm"
alias bat="batcat"
alias peas='wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O p'
alias mkreport="mkdir -p ACME/{Admin,Deliverables,Evidence/{Findings,Scans/{Vuln,Service,Web,'AD Enumeration'},Notes,OSINT,Wireless,'Logging output','Misc Files'},Retest}"
alias mkctf='mkdir files serve loot tools'
alias mkserve='rm -rf s && ln -s /opt/arsenal/serve s'
########### General CTF Aliases #############

########### HTB Aliases #############
alias htbvpn="sudo openvpn $HOME/HTB/VPN/release_arena_D3STY.ovpn"
alias htb="cd $HOME/HTB"
alias machines="cd $HOME/HTB/machines"
alias fort="cd $HOME/HTB/fortress"
alias challenges="cd $HOME/HTB/challenges"
alias htb="cd $HOME/HTB"
alias zephyr="$HOME/HTB/prolabs/zephyr"
alias dante="$HOME/HTB/prolabs/dante"
########### HTB Aliases #############

########### Vulnlab Aliases #############
alias vuln="cd $HOME/VL"
alias vmachines="cd $HOME/VL/machines"
alias chains="cd $HOME/VL/chains"
alias rtlabs="cd $HOME/VL/rtl"
alias vlvpn="sudo openvpn $HOME/VL/aws.ovpn"
alias rtvpn="sudo openvpn $HOME/VL/rtl-aws.ovpn"
########### Vulnlab Aliases #############