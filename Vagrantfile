# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box = "minimal/xenial64"
  config.ssh.pty = true
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y libssl-dev libffi-dev python-dev build-essential python-pip
    pip install --upgrade pip
    pip install -r requirements.txt
    echo "Now run  $ curl -L https://aka.ms/InstallAzureCli | bash"
  SHELL
end
