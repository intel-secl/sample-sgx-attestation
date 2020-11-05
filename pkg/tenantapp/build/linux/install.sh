#!/bin/bash

COMPONENT_NAME=sgx-tenant-app

SERVICE_USERNAME=sgx-tenant-app

if [[ $EUID -ne 0 ]]; then 
    echo "This installer must be run as root"
    exit 1
fi

echo "Setting up sgx-tenant-app Linux User..."
# useradd -M -> this user has no home directory
id -u $SERVICE_USERNAME 2> /dev/null || useradd -M --system --shell /sbin/nologin $SERVICE_USERNAME

echo "Installing sgx-tenant-app..."

PRODUCT_HOME=/opt/$COMPONENT_NAME
BIN_PATH=$PRODUCT_HOME/bin
LOG_PATH=/var/log/$COMPONENT_NAME/
CONFIG_PATH=/etc/$COMPONENT_NAME/
CERTS_PATH=$CONFIG_PATH/ca-certs

for directory in $BIN_PATH $LOG_PATH $CONFIG_PATH $CERTS_PATH; do
  # mkdir -p will return 0 if directory exists or is a symlink to an existing directory or directory and parents can be created
  mkdir -p $directory
  if [ $? -ne 0 ]; then
    echo_failure "Cannot create directory: $directory"
    exit 1
  fi
  chown -R $SERVICE_USERNAME:$SERVICE_USERNAME $directory
  chmod 700 $directory
  chmod g+s $directory
done

chown -R $SERVICE_USERNAME:$SERVICE_USERNAME $CONFIG_PATH
chmod -R 700 $CONFIG_PATH
chmod -R g+s $CONFIG_PATH

cp $COMPONENT_NAME $BIN_PATH/ && chown $SERVICE_USERNAME:$SERVICE_USERNAME $BIN_PATH/*
chmod 700 $BIN_PATH/*
ln -sfT $BIN_PATH/$COMPONENT_NAME /usr/bin/$COMPONENT_NAME

# make log files world readable
chmod 755 $LOG_PATH
chmod g+s $LOG_PATH

# Install systemd script
cp ${COMPONENT_NAME}.service $PRODUCT_HOME && chown $SERVICE_USERNAME:$SERVICE_USERNAME $PRODUCT_HOME/${COMPONENT_NAME}.service && chown $SERVICE_USERNAME:$SERVICE_USERNAME $PRODUCT_HOME

# Enable systemd service
systemctl disable ${COMPONENT_NAME}.service > /dev/null 2>&1
systemctl enable $PRODUCT_HOME/${COMPONENT_NAME}.service
systemctl daemon-reload

auto_install() {
  local component=${1}
  local cprefix=${2}
  local yum_packages=$(eval "echo \$${cprefix}_YUM_PACKAGES")
  # detect available package management tools. start with the less likely ones to differentiate.
  yum -y install $yum_packages
}

# find .env file 
echo PWD IS $(pwd)
if [ -f ~/${COMPONENT_NAME}.env ]; then
    echo Reading Installation options from `realpath ~/${COMPONENT_NAME}.env`
    env_file=~/${COMPONENT_NAME}.env
elif [ -f ../${COMPONENT_NAME}.env ]; then
    echo Reading Installation options from `realpath ../${COMPONENT_NAME}.env`
    env_file=../${COMPONENT_NAME}.env
fi

if [ -z $env_file ]; then
    echo "No .env file found"
    sgx-tenant-app_NOSETUP="true"
fi

# check if sgx-tenant-app_NOSETUP is defined
if [ "${sgx-tenant-app_NOSETUP,,}" == "true" ]; then
    echo "sgx-tenant-app_NOSETUP is true, skipping setup"
    echo "Run \"$COMPONENT_NAME setup all\" for manual setup"
    echo "Installation completed successfully!"
else 
    $COMPONENT_NAME setup all -f $env_file
    SETUPRESULT=$?
    chown -R sgx-tenant-app:sgx-tenant-app /etc/sgx-tenant-app/
    if [ ${SETUPRESULT} == 0 ]; then
        systemctl start $COMPONENT_NAME
        echo "Waiting for daemon to settle down before checking status"
        sleep 3
        systemctl status $COMPONENT_NAME 2>&1 > /dev/null
        if [ $? != 0 ]; then
            echo "Installation completed with Errors - $COMPONENT_NAME daemon not started."
            echo "Please check errors in syslog using \`journalctl -u $COMPONENT_NAME\`"
            exit 1
        fi
        echo "$COMPONENT_NAME daemon is running"
        echo "Installation completed successfully!"
    else 
        echo "Installation completed with errors"
    fi
fi