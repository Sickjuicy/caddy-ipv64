#!/bin/bash
echo '==================================='
echo 'Deploying Caddy to Production Server'
echo '==================================='

# Stop Caddy
echo 'Stopping Caddy...'
ssh root@caddy 'systemctl stop caddy'

# Copy new binary (using cat over SSH since scp might not be available)
echo 'Uploading new Caddy binary...'
cat ./caddy | ssh root@caddy 'cat > /tmp/caddy-new && chmod +x /tmp/caddy-new'

# Backup old version
echo 'Backing up old version...'
ssh root@caddy 'cp /usr/bin/caddy /usr/bin/caddy.backup-'

# Install new version
echo 'Installing new version...'
ssh root@caddy 'mv /tmp/caddy-new /usr/bin/caddy && chmod +x /usr/bin/caddy'

# Clean up old locks (wichtig!)
echo 'Cleaning up stale locks...'
ssh root@caddy 'rm -rf /var/lib/caddy/.local/share/caddy/locks/*'

# Start Caddy
echo 'Starting Caddy...'
ssh root@caddy 'systemctl start caddy'

# Show status
echo ''
echo 'Waiting 3 seconds for Caddy to start...'
sleep 3
echo ''
echo 'Caddy status:'
ssh root@caddy 'systemctl status caddy --no-pager -l | head -20'

echo ''
echo '==================================='
echo 'Deployment complete!'
echo '==================================='
