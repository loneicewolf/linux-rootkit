# Security EN/DIS ABLER
```sh
#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root (sudo ./unlock.sh)"
  exit
fi

echo "--- Kernel Security Toggle ---"
read -p "Do you want to DISABLE protections? (yes/no): " choice

if [[ "$choice" == "yes" ]]; then
    echo "[+] Setting SELinux to Permissive..."
    setenforce 0
    sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config

    echo "[+] Adding nokaslr and lockdown=none to GRUB..."
    # This line safely adds the parameters if they aren't there
    sed -i '/GRUB_CMDLINE_LINUX=/ s/\"$/ nokaslr lockdown=none\"/' /etc/default/grub
    
    echo "[+] Updating GRUB config..."
    grub2-mkconfig -o /boot/grub2/grub.cfg
    
    echo "--- DONE! Please reboot for KASLR/Lockdown changes to take effect. ---"

elif [[ "$choice" == "no" ]]; then
    echo "[-] Setting SELinux back to Enforcing..."
    setenforce 1
    sed -i 's/SELINUX=permissive/SELINUX=enforcing/g' /etc/selinux/config

    echo "[-] Removing nokaslr and lockdown=none from GRUB..."
    sed -i 's/ nokaslr//g' /etc/default/grub
    sed -i 's/ lockdown=none//g' /etc/default/grub
    
    echo "[-] Updating GRUB config..."
    grub2-mkconfig -o /boot/grub2/grub.cfg
    
    echo "--- DONE! Please reboot to restore protections. ---"
else
    echo "Invalid choice. Please type 'yes' or 'no'."
fi
```
