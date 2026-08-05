cd /var/www/html
git pull origin main
composer install --no-dev
npm run build
sudo systemctl restart php8.1-fpm
sudo systemctl restart apache2
tail -f /var/log/apache2/error.log
exit
