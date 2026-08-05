mysql -u root -pSup3rS3cr3t_Prod! payment_db
cd /var/www/html
git pull origin main
systemctl restart apache2
cat /home/admin/backup/db_config.txt
scp backup.sql admin@192.168.1.100:/backup/
ls -la /root/wallet.dat
python3 /opt/payment/process.py &
crontab -l
exit
