echo "n\n\n\n\nw" | fdisk /dev/sda
mkfs.ext4 /dev/sda
mount /dev/sda ~/SSD
