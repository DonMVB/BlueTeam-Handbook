# Ubuntu New Disk Setup Commands
# These commands will add a new disk and replace /cases directory

# Step 1: Identify the new disk
echo "=== Step 1: Identify the new disk ==="
lsblk
# Look for the new disk (likely /dev/sdb, /dev/sdc, etc.)
# Note: Replace /dev/sdb with your actual disk identifier throughout these commands

# Step 2: Create partition table and partition
echo "=== Step 2: Create partition on new disk ==="
# WARNING: This will destroy all data on the disk!
# Replace /dev/sdb with your actual disk
sudo fdisk /dev/sdb << EOF
n
p
1


w
EOF

# Alternative using parted (more reliable for scripting):
# sudo parted /dev/sdb --script mklabel gpt
# sudo parted /dev/sdb --script mkpart primary ext4 0% 100%

# Step 3: Format the partition with ext4 filesystem
echo "=== Step 3: Format the partition ==="
# Replace /dev/sdb1 with your actual partition
sudo mkfs.ext4 /dev/sdb1

# Step 4: Create temporary mount point and backup existing /cases data
echo "=== Step 4: Backup existing /cases data ==="
sudo mkdir -p /mnt/temp_cases
sudo mount /dev/sdb1 /mnt/temp_cases

# Copy existing data if any
if [ -d "/cases" ] && [ "$(ls -A /cases)" ]; then
    echo "Backing up existing /cases data..."
    sudo cp -a /cases/* /mnt/temp_cases/
    echo "Data backed up to new disk"
fi

# Step 5: Get the UUID of the new partition for fstab
echo "=== Step 5: Get partition UUID ==="
UUID=$(sudo blkid -s UUID -o value /dev/sdb1)
echo "Partition UUID: $UUID"

# Step 6: Unmount temporary mount and prepare for permanent mount
echo "=== Step 6: Prepare for permanent mount ==="
sudo umount /mnt/temp_cases
sudo rmdir /mnt/temp_cases

# Step 7: Remove old /cases directory and recreate as mount point
echo "=== Step 7: Recreate /cases as mount point ==="
sudo rm -rf /cases
sudo mkdir /cases

# Step 8: Add entry to /etc/fstab for permanent mounting
echo "=== Step 8: Add to /etc/fstab ==="
# Backup fstab first
sudo cp /etc/fstab /etc/fstab.backup.$(date +%Y%m%d_%H%M%S)

# Add the new mount entry
echo "UUID=$UUID /cases ext4 defaults 0 2" | sudo tee -a /etc/fstab

# Step 9: Mount the new disk
echo "=== Step 9: Mount the new disk ==="
sudo mount -a
# Or specifically: sudo mount /cases

# Step 10: Set proper ownership and permissions for Samba
echo "=== Step 10: Set Samba permissions and ownership ==="
# Set group ownership to sambausers
sudo chgrp sambausers /cases

# Set permissions (775 = rwxrwxr-x)
sudo chmod 775 /cases

# Step 11: Verify the setup
echo "=== Step 11: Verify setup ==="
echo "Disk space:"
df -h /cases

echo "Mount information:"
mount | grep /cases

echo "Permissions:"
ls -ld /cases

echo "Group membership:"
getent group sambausers

# Step 12: Test Samba access (optional)
echo "=== Step 12: Test Samba functionality ==="
# Restart Samba services to ensure they recognize the new mount
sudo systemctl restart smbd nmbd

# Test local Samba access
echo "Testing Samba share access..."
smbclient -L localhost -N 2>/dev/null | grep cases

echo "=== Setup Complete ==="
echo "The new disk is now mounted at /cases with proper Samba permissions"
echo "Disk UUID: $UUID"
echo "Samba share should be accessible at: //$(hostname -I | awk '{print $1}')/cases"
