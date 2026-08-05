#!/bin/bash
# Nightly backup - payment_db + web root
# TODO: fix permissions on this file (world-writable, flagged in code review 2026-01)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mysqldump -u root -pSup3rS3cr3t_Prod! payment_db > /home/admin/backup/db_dump_${TIMESTAMP}.sql
tar -czf /home/admin/backup/www_${TIMESTAMP}.tar.gz /var/www/html
find /home/admin/backup -name "*.sql" -mtime +7 -delete
echo "Backup completed at $(date)" >> /var/log/backup.log
