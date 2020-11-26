#!/bin/bash

COMPONENT_NAME=sgx-app-verifier
SERVICE_USERNAME=sgx-app-verifier

if [[ $EUID -ne 0 ]]; then 
    echo "This installer must be run as root"
    exit 1
fi

echo "Setting up sgx-app-verifier Linux User..."
# useradd -M -> this user has no home directory
id -u $SERVICE_USERNAME 2> /dev/null || useradd -M --system --shell /sbin/nologin $SERVICE_USERNAME

echo "Installing sgx-app-verifier..."

PRODUCT_HOME=/opt/$COMPONENT_NAME
BIN_PATH=$PRODUCT_HOME/bin
LOG_PATH=/var/log/$COMPONENT_NAME/
CONFIG_PATH=/etc/$COMPONENT_NAME/

for directory in $BIN_PATH $LOG_PATH $CONFIG_PATH; do
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

cp sgx-quote-policy.txt $CONFIG_PATH
chown -R $SERVICE_USERNAME:$SERVICE_USERNAME $CONFIG_PATH
chmod -R 700 $CONFIG_PATH
chmod -R g+s $CONFIG_PATH

cp $COMPONENT_NAME $BIN_PATH/ && chown $SERVICE_USERNAME:$SERVICE_USERNAME $BIN_PATH/*
chmod 700 $BIN_PATH/*
ln -sfT $BIN_PATH/$COMPONENT_NAME /usr/bin/$COMPONENT_NAME

# make log files world readable
chmod 755 $LOG_PATH
chmod g+s $LOG_PATH

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
    SGXAPPVERIFIER_NOSETUP="true"
fi

# check if SGXAPPVERIFIER_NOSETUP is defined
if [ "${SGXAPPVERIFIER_NOSETUP}" == "true" ]; then
    echo "SGXAPPVERIFIER_NOSETUP is true, skipping setup"
    echo "Run \"$COMPONENT_NAME setup all\" for manual setup"
    echo "Installation completed successfully!"
else 
    $COMPONENT_NAME setup -f $env_file
    SETUPRESULT=$?
    chown -R sgx-app-verifier:sgx-app-verifier "$CONFIG_PATH"
    if [ ${SETUPRESULT} == 0 ]; then
        echo "Installation completed successfully!"
    else 
        echo "Installation completed with errors"
    fi
fi
