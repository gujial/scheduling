{ pkgs, modulesPath, ... }: {
  imports = [ (modulesPath + "/virtualisation/qemu-vm.nix") ];

  boot.kernelPackages = pkgs.linuxPackages_latest; 
  
  boot.kernelPatches = [ {
    name = "sched_ext_config";
    patch = null;
    extraConfig = ''
      SCHED_CLASS_EXT y
      DEBUG_INFO_BTF y
      BPF_SYSCALL y
    '';
  } ];

  networking.hostName = "ebpf-test-vm";
  services.getty.autologinUser = "root";

  environment.systemPackages = with pkgs; [
    llvmPackages_18.clang-unwrapped
    clang_18
    llvm_18
    bpftools
    libbpf
    elfutils
    pahole
    gnumake
    gcc
    pkg-config
    zlib
    libelf
  ];

  environment.variables = {
    PKG_CONFIG_PATH = "${pkgs.libbpf}/lib/pkgconfig";
    CPATH = "${pkgs.libbpf}/include";
  };

  # 共享开发目录（将宿主机的代码目录挂载到 VM 内）
  virtualisation.sharedDirectories.src = {
    source = "/mnt/repos/scheduling"; # 宿主机当前目录
    target = "/src"; # VM 内挂载点
  };

  virtualisation.qemu.options = [ "-m 4G" "-smp 4" ];
}