#!/bin/sh

export PGPASSWORD=`cat /home/postgresql/admin.db.password`

date=`date | tr ' ' '-'`

backup_file="/root/backups/postgresql/backup-$date.txt"
zip_file="/root/backups/postgresql/backup-$date.tgz"

/usr/local/bin/pg_dumpall -U postgres > $backup_file
cp $backup_file /root/backups/postgresql/backup.txt

tar -cvzf $zip_file $backup_file 
rm -rf $backup_file 

if [ "$?" == "0" ]
then
        rm -rf $zip_file
        /usr/local/bin/tarsnap -cf "$(uname -n)-$(date +%Y-%m-%d_%H-%M-%S)" /root/backups/postgresql/backup.txt
fi
