#!/bin/bash

# System Setup and Optimization Script
# This script configures logging, installs xandminer, and optimizes the system

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Parse command line arguments
parse_arguments() {
    INSTALL_XANDMINER="false"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --install-xandminer)
                INSTALL_XANDMINER="true"
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Show help information
show_help() {
    echo "System Setup and Optimization Script"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --install-xandminer    Include Xandminer installation"
    echo "  -h, --help            Show this help message"
    echo
    echo "Examples:"
    echo "  $0                           # Run without Xandminer"
    echo "  $0 --install-xandminer       # Run with Xandminer installation"
}

# Update system and install dependencies
install_dependencies() {
    log "Updating system packages..."
    apt update
    
    log "Installing cron..."
    apt install cron -y
    
    log "Enabling and starting cron service..."
    systemctl enable cron
    systemctl start cron
}

# Install Xandminer (optional)
install_xandminer() {
    if [[ "$INSTALL_XANDMINER" == "true" ]]; then
        log "Installing Xandminer..."
        wget -O install.sh "https://raw.githubusercontent.com/Xandeum/xandminer-installer/refs/heads/master/install.sh"
        chmod a+x install.sh
        ./install.sh
        rm -f install.sh
        log "Xandminer installation completed"
    else
        info "Skipping Xandminer installation (use --install-xandminer flag to include)"
    fi
}

# Configure journal logging
configure_journald() {
    log "Configuring systemd journal logging..."
    
    cat > /etc/systemd/journald.conf << 'EOF'
[Journal]
SystemMaxUse=200M
SystemMaxFileSize=50M
SystemMaxFiles=5
MaxRetentionSec=1week
RuntimeMaxUse=50M
EOF

    log "Restarting systemd-journald..."
    systemctl restart systemd-journald
}

# Configure logrotate
configure_logrotate() {
    log "Configuring logrotate..."
    
    cat > /etc/logrotate.conf << 'EOF'
# see "man logrotate" for details

# global options do not affect preceding include directives

# Rotate logs daily instead of weekly
daily

# use the adm group by default, since this is the owning group
# of /var/log/.
su root adm

# Keep only 3 days of logs instead of 4 weeks
rotate 3

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
#dateext

# Compress logs immediately
compress
delaycompress

# Remove logs older than 3 days
maxage 3

# packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may also be configured here.
EOF

    log "Logrotate configuration updated"
}

# Configure system optimizations
configure_system_optimizations() {
    log "Configuring system optimizations..."
    
    # Disable crash reports (saves space)
    systemctl disable apport 2>/dev/null || true
    
    # Limit package cache size
    echo 'APT::Cache-Limit "100000000";' | tee /etc/apt/apt.conf.d/70debconf > /dev/null
    echo 'APT::Cache-Start "100000000";' | tee -a /etc/apt/apt.conf.d/70debconf > /dev/null
    
    # Auto-clean package cache weekly
    echo 'APT::Periodic::AutocleanInterval "7";' | tee /etc/apt/apt.conf.d/02periodic > /dev/null
    
    log "System optimizations configured"
}

# Create cleanup script and cron job
create_cleanup_script() {
    log "Creating cleanup script..."
    
    cat > /usr/local/bin/cleanup-logs << 'EOF'
#!/bin/bash

# Clean logs older than 3 days
journalctl --vacuum-time=3d
journalctl --vacuum-size=200M

# Clean package cache
apt autoremove -y
apt autoclean

# Clean temp files
find /tmp -type f -atime +1 -delete 2>/dev/null || true
find /var/tmp -type f -atime +1 -delete 2>/dev/null || true
EOF

    chmod +x /usr/local/bin/cleanup-logs
    
    # Add cron job for daily cleanup at 3 AM
    log "Adding cron job for daily cleanup..."
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/cleanup-logs") | crontab -
    
    log "Cleanup script and cron job created"
}

# Configure headless boot mode
configure_headless_mode() {
    log "Configuring headless boot mode..."
    
    # Check current boot target
    current_target=$(systemctl get-default)
    info "Current boot target: $current_target"
    
    # Switch to headless boot mode
    systemctl set-default multi-user.target
    
    # Blacklist graphics driver to stop QXL errors
    echo "blacklist qxl" >> /etc/modprobe.d/blacklist-graphics.conf
    
    # Remove desktop environments and graphics packages
    log "Removing desktop environments and graphics packages..."
    apt remove --purge ubuntu-desktop* gnome-* kde-* xfce4* lxde* -y 2>/dev/null || true
    apt remove --purge xserver-xorg* lightdm* gdm3* -y 2>/dev/null || true
    apt remove --purge plymouth* -y 2>/dev/null || true
    apt remove --purge gsettings-desktop-schemas python3-xkit -y 2>/dev/null || true
    
    # Clean up everything
    apt autoremove --purge -y
    apt autoclean
    
    log "Headless mode configuration completed"
}

# Fix pod service symlink
fix_pod_service() {
    log "Fixing pod service symlink..."
    
    # Create symlink if it doesn't exist
    if [[ ! -L /run/xandeum-pod ]]; then
        ln -sf /xandeum-pages /run/xandeum-pod
        log "Created symlink: /run/xandeum-pod -> /xandeum-pages"
    else
        info "Symlink already exists"
    fi
    
    # Restart pod service if it exists
    if systemctl list-unit-files | grep -q "pod.service"; then
        log "Restarting pod service..."
        systemctl restart pod.service || warn "Failed to restart pod service"
    else
        info "Pod service not found, skipping restart"
    fi
}

# Clean existing logs for fresh start
clean_existing_logs() {
    log "Cleaning existing logs for fresh start..."
    journalctl --vacuum-time=1s
}

# Update initramfs
update_initramfs() {
    log "Updating initramfs to apply driver blacklist..."
    update-initramfs -u
}

# Display system status
show_system_status() {
    echo
    log "============================================="
    log "System Setup and Optimization Complete!"
    log "============================================="
    echo
    info "Current disk usage:"
    df -h / | tail -1
    echo
    info "Largest space users:"
    du -sh /* 2>/dev/null | sort -h | tail -5
    echo
    info "Service Status:"
    echo "  - Cron: $(systemctl is-active cron 2>/dev/null || echo 'inactive')"
    echo "  - Pod: $(systemctl is-active pod.service 2>/dev/null || echo 'not found')"
    echo "  - Xandminer: $(systemctl is-active xandminer.service 2>/dev/null || echo 'not found')"
    echo "  - Xandminerd: $(systemctl is-active xandminerd.service 2>/dev/null || echo 'not found')"
    echo
    info "Boot target: $(systemctl get-default)"
    echo
    info "Useful commands for monitoring:"
    echo "  - Check recent cron logs: journalctl -u cron --since '10 minutes ago'"
    echo "  - Check system errors: journalctl --since '1 hour ago' --priority=err"
    echo "  - Check pod service: systemctl status pod.service -l"
    echo "  - Run cleanup manually: /usr/local/bin/cleanup-logs"
    echo "  - Check disk usage: df -h"
    echo
    warn "REBOOT REQUIRED to apply all changes!"
    info "Run 'sudo reboot' to complete the setup"
}

# Ask for reboot confirmation
ask_reboot() {
    echo
    read -p "Do you want to reboot now to apply all changes? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Rebooting system..."
        sleep 2
        reboot
    else
        warn "Remember to reboot later to apply all changes!"
    fi
}

# Cleanup function for script interruption
cleanup() {
    error "Script interrupted. Some changes may be incomplete."
    exit 1
}

# Main installation function
main() {
    trap cleanup INT TERM
    
    # Parse command line arguments first
    parse_arguments "$@"
    
    log "Starting System Setup and Optimization..."
    if [[ "$INSTALL_XANDMINER" == "true" ]]; then
        info "Xandminer installation: ENABLED"
    else
        info "Xandminer installation: DISABLED (use --install-xandminer to enable)"
    fi
    
    check_root
    install_dependencies
    install_xandminer
    configure_journald
    configure_logrotate
    configure_system_optimizations
    create_cleanup_script
    configure_headless_mode
    fix_pod_service
    clean_existing_logs
    update_initramfs
    show_system_status
    ask_reboot
}

# Run the main function
main "$@"
