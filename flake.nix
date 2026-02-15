{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
  in {
    nixosConfigurations.ebpf-vm = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./vm.nix
      ];
    };

    devShells.${system}.default = pkgs.mkShell {
      buildInputs = with pkgs; [
        clang_18
        llvm_18
        bpftools
        libbpf
        elfutils
        pahole
        gdb
        qemu_kvm
      ];

      shellHook = ''
        export BPF_CLANG=${pkgs.clang_18}/bin/clang
      '';
    };
  };
}