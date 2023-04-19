{
  description = "Helpers for parsing pcap files";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    with import nixpkgs ({ system = "x86_64-linux"; });
    with python3.pkgs; {
      packages.${system}.default = buildPythonPackage {
        pname = "pcap_utils";
        version = "0.0.1";
        format = "maturin";
        src = lib.cleanSource ./.;
        cargoDeps = rustPlatform.importCargoLock { lockFile = ./Cargo.lock; };
        nativeBuildInputs = with rustPlatform; [
          cargoSetupHook
          maturinBuildHook
        ];
        buildInputs = [ libpcap ];
        pythonImportsCheck = [ "pcap_utils" ];

        # for testing
        WIRESHARK_SRC = wireshark.src;
      };
    };
}
