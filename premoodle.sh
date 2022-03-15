#!/bin/bash

PhpVer=7.4
# moodleVersion=MOODLE_311_STABLE
moodleVersion=v3.11.5
siteFQDN=www.prueba.com
thumbprintSslCert=None
moodledbname=moodle

# httpsTermination=VMSS
httpsTermination=None

. ./funciones.sh
    # borrar ficheros anteriores de tmp
    sudo rm -rf /tmp/apt*
    sudo rm -rf /tmp/*moodle*
    #Updating php sources
    sudo add-apt-repository -y ppa:ondrej/php  
    sudo add-apt-repository -y ppa:ubuntu-toolchain-r/ppa
    sudo apt-get -y update > /dev/null 2>&1
    sudo apt-get -y install software-properties-common unzip unattended-upgrades fail2ban


    # if [ "$dbServerType" = "mysql" ]; then
    #   mysqlIP=$dbIP
    #   mysqladminlogin=$dbadminloginazure
    #   mysqladminpass=$dbadminpass
    
    # else
    #   echo "Invalid dbServerType ($dbServerType) given. Only 'mysql' or 'postgres' or 'mssql' is allowed. Exiting"
    #   exit 1
    # fi

    # make sure system does automatic updates and fail2ban
    configurarfail2ban

    # create gluster, nfs or Azure Files mount point
    echo "creando estructura"
    sudo mkdir -p /moodle
    sudo chown -R $USER:$USER /moodle

    # Set up initial moodle dirs
    mkdir -p /moodle/html
    mkdir -p /moodle/certs
    mkdir -p /moodle/moodledata


    export DEBIAN_FRONTEND=noninteractive
    sudo apt-get -y  --allow-change-held-packages install rsyslog git  cifs-utils mysql-client     >> /tmp/apt3.log

    # If its a migration flow, then mount the azure file share now.
    if [ "$isMigration" = "true" ]; then
        # On migration flow, the moodle azure file share must present before running this script.
        echo -e '\n\rIts a migration flow, check whether moodle fileshare exists\n\r'
        check_azure_files_moodle_share_exists $storageAccountName $storageAccountKey
        
        # Set up and mount Azure Files share.
        echo -e '\n\rSetting up and mounting Azure Files share //'$storageAccountName'.file.core.windows.net/moodle on /moodle\n\r'
        setup_and_mount_azure_files_moodle_share $storageAccountName $storageAccountKey
    fi



    # install the entire stack
    instalarphp
    
    # install Moodle 
    instalarmoodle

    # nginx config
    instalarnginx

    configurarvarnish

   
    if [ $dbServerType = "mysql" ]; then
        mysql -h $mysqlIP -u $mysqladminlogin -p${mysqladminpass} -e "CREATE DATABASE ${moodledbname} CHARACTER SET utf8;"
        mysql -h $mysqlIP -u $mysqladminlogin -p${mysqladminpass} -e "GRANT ALL ON ${moodledbname}.* TO ${moodledbuser} IDENTIFIED BY '${moodledbpass}';"

        echo "mysql -h $mysqlIP -u $mysqladminlogin -p${mysqladminpass} -e \"CREATE DATABASE ${moodledbname};\"" >> /tmp/debug
        echo "mysql -h $mysqlIP -u $mysqladminlogin -p${mysqladminpass} -e \"GRANT ALL ON ${moodledbname}.* TO ${moodledbuser} IDENTIFIED BY '${moodledbpass}';\"" >> /tmp/debug
    fi

    # Master config for syslog
    sudo mkdir /var/log/sitelogs
    sudo chown syslog.adm /var/log/sitelogs
    cat <<EOF >> /etc/rsyslog.conf
\$ModLoad imudp
\$UDPServerRun 514
EOF
    cat <<EOF >> /etc/rsyslog.d/40-sitelogs.conf
local1.*   /var/log/sitelogs/moodle/access.log
local1.err   /var/log/sitelogs/moodle/error.log
local2.*   /var/log/sitelogs/moodle/cron.log
EOF
    sudo systemctl restart rsyslog 

    # Fire off moodle setup
    if [ "$httpsTermination" = "None" ]; then
        siteProtocol="http"
    else
        siteProtocol="https"
    fi
    if [ $dbServerType = "mysql" ]; then
        if [ "$isMigration" = "true" ]; then
            echo "Importing database from the mysql dump file"
            if [ ! -f /moodle/migration-db-moodle.sql.tar.gz ]; then
              echo "Migrating moodle DB dump archive file not found."
              exit 1
            fi
            
            tar -xvf /moodle/migration-db-moodle.sql.tar.gz -C /moodle/
            
            if [ ! -f /moodle/migration-db-moodle.sql ]; then
              echo "Migrating moodle DB dump file not found."
              exit 1
            fi
            
            echo "Importing migration moodle DB."
            mysql -h $mysqlIP -u $mysqladminlogin -p${mysqladminpass} ${moodledbname} < /moodle/migration-db-moodle.sql
            
            echo "Updating moodle db config settings"
            replace_moodle_config_value "dbhost" "$mysqlIP"
            replace_moodle_config_value "dbuser" "$azuremoodledbuser"
            replace_moodle_config_value "dbpass" "$moodledbpass"
            
            echo "Updating other moodle config settings"
            replace_moodle_config_value "dataroot" "\/moodle\/moodledata"
            replace_moodle_config_value "wwwroot" "$siteProtocol:\/\/$siteFQDN"
        else
            echo -e "cd /tmp; /usr/bin/php /moodle/html/moodle/admin/cli/install.php --chmod=770 --lang=en --wwwroot="$siteProtocol"://"$siteFQDN" --dataroot=/moodle/moodledata --dbhost="$mysqlIP" --dbname="$moodledbname" --dbuser="$azuremoodledbuser" --dbpass="$moodledbpass" --dbtype=mysqli --fullname='Moodle LMS' --shortname='Moodle' --adminuser=admin --adminpass="$adminpass" --adminemail=admin@"$siteFQDN" --non-interactive --agree-license --allow-unstable || true "
            cd /tmp; /usr/bin/php /moodle/html/moodle/admin/cli/install.php --chmod=770 --lang=en --wwwroot=$siteProtocol://$siteFQDN   --dataroot=/moodle/moodledata --dbhost=$mysqlIP   --dbname=$moodledbname   --dbuser=$azuremoodledbuser   --dbpass=$moodledbpass   --dbtype=mysqli --fullname='Moodle LMS' --shortname='Moodle' --adminuser=admin --adminpass=$adminpass   --adminemail=admin@$siteFQDN   --non-interactive --agree-license --allow-unstable || true
        fi

        if [ "$installObjectFsSwitch" = "true" ]; then
            mysql -h $mysqlIP -u $mysqladminlogin -p${mysqladminpass} ${moodledbname} -e "INSERT INTO mdl_config_plugins (plugin, name, value) VALUES ('tool_objectfs', 'enabletasks', 1);" 
            mysql -h $mysqlIP -u $mysqladminlogin -p${mysqladminpass} ${moodledbname} -e "INSERT INTO mdl_config_plugins (plugin, name, value) VALUES ('tool_objectfs', 'filesystem', '\\\tool_objectfs\\\azure_file_system');"
            mysql -h $mysqlIP -u $mysqladminlogin -p${mysqladminpass} ${moodledbname} -e "INSERT INTO mdl_config_plugins (plugin, name, value) VALUES ('tool_objectfs', 'azure_accountname', '${storageAccountName}');"
            mysql -h $mysqlIP -u $mysqladminlogin -p${mysqladminpass} ${moodledbname} -e "INSERT INTO mdl_config_plugins (plugin, name, value) VALUES ('tool_objectfs', 'azure_container', 'objectfs');"
            mysql -h $mysqlIP -u $mysqladminlogin -p${mysqladminpass} ${moodledbname} -e "INSERT INTO mdl_config_plugins (plugin, name, value) VALUES ('tool_objectfs', 'azure_sastoken', '${sas}');"
        fi
    fi

    echo -e "\n\rDone! Installation completed!\n\r"
    
    # use /tmp/localcachedir/ for localcache and /var/www/html/moodle/ for core_component.php
    dir="/var/www/html/moodle"
    if [[ ! -d $dir ]]; then
        mkdir -p $dir
    fi
    sed -i "22 a \$CFG->localcachedir = '/tmp/localcachedir';" /moodle/html/moodle/config.php
    sed -i "22 a \$CFG->alternative_component_cache = '/var/www/html/moodle/core_component.php';" /moodle/html/moodle/config.php
    chown -R www-data:www-data $dir
    chgrp www-data $dir
    chmod g+s $dir
    
    if [ "$redisAuth" != "None" ]; then
        create_redis_configuration_in_moodledata_muc_config_php

        # redis configuration in /moodle/html/moodle/config.php
        sed -i "23 a \$CFG->session_redis_lock_expire = 7200;" /moodle/html/moodle/config.php
        sed -i "23 a \$CFG->session_redis_acquire_lock_timeout = 120;" /moodle/html/moodle/config.php
        sed -i "23 a \$CFG->session_redis_prefix = 'moodle_prod'; // Optional, default is don't set one." /moodle/html/moodle/config.php
        sed -i "23 a \$CFG->session_redis_database = 0;  // Optional, default is db 0." /moodle/html/moodle/config.php
        sed -i "23 a \$CFG->session_redis_port = 6379;  // Optional." /moodle/html/moodle/config.php
        sed -i "23 a \$CFG->session_redis_host = '$redisDns';" /moodle/html/moodle/config.php
        sed -i "23 a \$CFG->session_redis_auth = '$redisAuth';" /moodle/html/moodle/config.php
        sed -i "23 a \$CFG->session_handler_class = '\\\core\\\session\\\redis';" /moodle/html/moodle/config.php
    fi

    if [ "$httpsTermination" != "None" ]; then
        # We proxy ssl, so moodle needs to know this
        sed -i "23 a \$CFG->sslproxy  = 'true';" /moodle/html/moodle/config.php
    fi

    if [ "$searchType" = "elastic" ]; then
        # Set up elasticsearch plugin
        if [ "$tikaVmIP" = "none" ]; then
           sed -i "23 a \$CFG->forced_plugin_settings = ['search_elastic' => ['hostname' => 'http://$elasticVm1IP']];" /moodle/html/moodle/config.php
        else
           sed -i "23 a \$CFG->forced_plugin_settings = ['search_elastic' => ['hostname' => 'http://$elasticVm1IP', 'fileindexing' => 'true', 'tikahostname' => 'http://$tikaVmIP', 'tikaport' => '9998'],];" /moodle/html/moodle/config.php
        fi

        sed -i "23 a \$CFG->searchengine = 'elastic';" /moodle/html/moodle/config.php
        sed -i "23 a \$CFG->enableglobalsearch = 'true';" /moodle/html/moodle/config.php
        # create index
        php /moodle/html/moodle/search/cli/indexer.php --force --reindex

    elif [ "$searchType" = "azure" ]; then
        # Set up Azure Search service plugin
        if [ "$tikaVmIP" = "none" ]; then
           sed -i "23 a \$CFG->forced_plugin_settings = ['search_azure' => ['searchurl' => 'https://$azureSearchNameHost', 'apikey' => '$azureSearchKey']];" /moodle/html/moodle/config.php
        else
           sed -i "23 a \$CFG->forced_plugin_settings = ['search_azure' => ['searchurl' => 'https://$azureSearchNameHost', 'apikey' => '$azureSearchKey', 'fileindexing' => '1', 'tikahostname' => 'http://$tikaVmIP', 'tikaport' => '9998'],];" /moodle/html/moodle/config.php
        fi

        sed -i "23 a \$CFG->searchengine = 'azure';" /moodle/html/moodle/config.php
        sed -i "23 a \$CFG->enableglobalsearch = 'true';" /moodle/html/moodle/config.php
        # create index
        php /moodle/html/moodle/search/cli/indexer.php --force --reindex

    fi

    if [ "$installObjectFsSwitch" = "true" ]; then
        # Set the ObjectFS alternate filesystem
        sed -i "23 a \$CFG->alternative_file_system_class = '\\\tool_objectfs\\\azure_file_system';" /moodle/html/moodle/config.php
    fi

   if [ "$dbServerType" = "postgres" ]; then
     # Get a new version of Postgres to match Azure version
     add-apt-repository "deb http://apt.postgresql.org/pub/repos/apt/ xenial-pgdg main"
     wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
     apt-get update
     apt-get install -y postgresql-client-9.6
   fi

   # create cron entry
   # It is scheduled for once per minute. It can be changed as needed.
   echo '* * * * * www-data /usr/bin/php /moodle/html/moodle/admin/cli/cron.php 2>&1 | /usr/bin/logger -p local2.notice -t moodle' > /etc/cron.d/moodle-cron

   # Set up cronned sql dump
   if [ "$dbServerType" = "mysql" ]; then
      cat <<EOF > /etc/cron.d/sql-backup
22 02 * * * root /usr/bin/mysqldump -h $mysqlIP -u ${azuremoodledbuser} -p'${moodledbpass}' --databases ${moodledbname} | gzip > /moodle/db-backup.sql.gz
EOF
   elif [ "$dbServerType" = "postgres" ]; then
      cat <<EOF > /etc/cron.d/sql-backup
22 02 * * * root /usr/bin/pg_dump -Fc -h $postgresIP -U ${azuremoodledbuser} ${moodledbname} > /moodle/db-backup.sql
EOF
   #else # mssql. TODO It's missed earlier! Complete this!
   fi

   # Turning off services we don't need the controller running
   sudo systemctl stop nginx
   sudo systemctl stop php${PhpVer}-fpm
   sudo systemctl stop varnish
   sudo systemctl stop varnishncsa
   #service varnishlog stop

    # No need to run the commands below any more, as permissions & modes are already as such (no more "sudo -u www-data ...")
    # Leaving this code as a remark that we are explicitly leaving the ownership to root:root
#    if [ $fileServerType = "gluster" -o $fileServerType = "nfs" -o $fileServerType = "nfs-ha" ]; then
#       # make sure Moodle can read its code directory but not write
#       sudo chown -R root.root /moodle/html/moodle
#       sudo find /moodle/html/moodle -type f -exec chmod 644 '{}' \;
#       sudo find /moodle/html/moodle -type d -exec chmod 755 '{}' \;
#    fi
    # But now we need to adjust the moodledata and the certs directory ownerships, and the permission for the generated config.php
    sudo chown -R www-data.www-data /moodle/moodledata /moodle/certs
    sudo chmod +r /moodle/html/moodle/config.php

    # chmod /moodle for Azure NetApp Files (its default is 770!)
    if [ $fileServerType = "nfs-byo" ]; then
        sudo chmod +rx /moodle
    fi

   if [ $fileServerType = "azurefiles" ]; then
      if [ "$isMigration" = "true" ]; then
        echo -e '\n\rIts a migration flow, the moodle content is already on azure file share\n\r'
      else
         # Delayed copy of moodle installation to the Azure Files share

         # First rename moodle directory to something else
         mv /moodle /moodle_old_delete_me
         # Then create the moodle share
         echo -e '\n\rCreating an Azure Files share for moodle'
         create_azure_files_moodle_share $storageAccountName $storageAccountKey /tmp/wabs.log $fileServerDiskSize
         # Set up and mount Azure Files share. Must be done after nginx is installed because of www-data user/group
         echo -e '\n\rSetting up and mounting Azure Files share on //'$storageAccountName'.file.core.windows.net/moodle on /moodle\n\r'
         setup_and_mount_azure_files_moodle_share $storageAccountName $storageAccountKey
         # Move the local installation over to the Azure Files
         echo -e '\n\rMoving locally installed moodle over to Azure Files'

         # install azcopy
         wget -q -O azcopy_v10.tar.gz https://aka.ms/downloadazcopy-v10-linux && tar -xf azcopy_v10.tar.gz --strip-components=1 && mv ./azcopy /usr/bin/
      
         ACCOUNT_KEY="$storageAccountKey"
         NAME="$storageAccountName"
         END=`date -u -d "60 minutes" '+%Y-%m-%dT%H:%M:00Z'`

         sas=$(az storage share generate-sas \
           -n moodle \
           --account-key $ACCOUNT_KEY \
           --account-name $NAME \
           --https-only \
           --permissions lrw \
           --expiry $END -o tsv)

         export AZCOPY_CONCURRENCY_VALUE='48'
         export AZCOPY_BUFFER_GB='4'

         # cp -a /moodle_old_delete_me/* /moodle || true # Ignore case sensitive directory copy failure
         azcopy --log-level ERROR copy "/moodle_old_delete_me/*" "https://$NAME.file.core.windows.net/moodle?$sas" --recursive || true # Ignore case sensitive directory copy failure
         rm -rf /moodle_old_delete_me || true # Keep the files just in case
      fi
   fi

   create_last_modified_time_update_script
   run_once_last_modified_time_update_script

   echo "### Script End `date`###"

}  2>&1 | tee /tmp/install.log

