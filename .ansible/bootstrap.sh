#!/bin/bash

# Updating and preparing system for ansible
sudo apt-get update && sudo apt-get install -y python ansible

# Cleanup the ansible roles folder
echo "Cleaning ansible roles folder..."
rm -rf /vagrant/.ansible/roles

# Install required roles from roles.yml file
echo "Installing ansible roles to provision with vagrant..."
ansible-galaxy install --roles-path /vagrant/.ansible/roles -r /vagrant/.ansible/roles.yml