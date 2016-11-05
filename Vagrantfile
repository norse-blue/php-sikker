# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/xenial64"
  config.vm.hostname = "sikker"
  config.vm.provider "virtualbox" do |vb|
  	vb.memory = 1024
  	vb.cpus = 1
  end
  config.vm.provision "shell", path: "./.ansible/bootstrap.sh"
  config.vm.provision "ansible" do |ansible|
  	ansible.playbook = "./.ansible/webdev.yml"
    ansible.verbose = ""
  end
end
