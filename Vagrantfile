Vagrant.configure("2") do |config|
  config.vm.box = "jacobw/fedora35-arm64"
  config.vm.synced_folder ".", "/root/go/src/github.com/lukehinds/tpm-sigstore-sign", type: "rsync",
    rsync__exclude: ".git/"
  config.vm.box_version = "3.6.8"
end
