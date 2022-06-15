Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-20.04-arm64"
  config.vm.box_version = "202112.19.0"
  config.vm.synced_folder ".", "/root/go/src/github.com/lukehinds/tpm-sigstore-sign", type: "rsync",
    rsync__exclude: ".git/"
end
