mkdir -p /root/backups/postgresql

cp backup.sh /root/
echo /root/backup.sh >> /etc/daily.local

mkdir /root/tarsnap-install
cd /root/tarsnap-install

ftp https://www.tarsnap.com/download/tarsnap-autoconf-1.0.39.tgz

tar -xzf tarsnap-autoconf-1.0.39.tgz
cd tarsnap-autoconf-1.0.39/

./configure
make all
make install

cp /usr/local/etc/tarsnap.conf.sample /usr/local/etc/tarsnap.conf

# TODO: please change the --user and --machine accordingly
tarsnap-keygen --keyfile /root/tarsnap.key --user auth@iudx.org.in --machine auth.iudx.org.in 

