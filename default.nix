{
  rustPlatform,
  protobuf,
  pcsclite,
  pkg-config,
  binaryen,

  wasm-pack,
  wasm-bindgen-cli_0_2_108,
  writableTmpDirAsHomeHook,
  lld,
  wasm ? false,
}:
let
  pname = "meesign-crypto";
  version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
  src = ./.;
  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "bulletproof-kzen-1.2.1" = "sha256-/J3L2oQ0VCV0D9wgePEXrC5FedBezM/Jqfy8ICUWUtY";
      "centipede-0.3.1" = "sha256-HGyE0lmaMQ1uVe5IWMOb/3BJXW6ZaguKixIVklNOhGo";
      "curv-kzen-0.10.0" = "sha256-tvZnrglzBBy+fusOy0i7db502nLPDCJTNZUHdi5DBq8";
      "frost-core-0.7.0" = "sha256-NVkgX9v+sAi8Hpalxw8KfURfOjMUSk+xMcnK+s9C7rE=";
      "kzen-paillier-0.4.3" = "sha256-Ych1uPKGPywr3Ki96ICeXJJmB0EinPImLaVHW2OM5Fw=";
      "mpecdsa-0.3.2" = "sha256-aZ5RIqYN78/iPLN0GfSJ46EFsqWkrsDjSzn4pTDEU/g";
      "multi-party-ecdsa-0.8.1" = "sha256-0lMYpVmP4ZuUP26J0mP9fc13iWtT9DMu1NQ34v1Wpvg=";
      "zk-paillier-0.4.4" = "sha256-elV8yiKWoY1tlkrHhlX7poqIJjm8PR63zaJ392N65Bg";
    };
  };

  wasmModules = rustPlatform.buildRustPackage {
    inherit pname version src cargoLock;

    name = "${pname}-wasm-modules-${version}";

    nativeBuildInputs = [
      protobuf
      writableTmpDirAsHomeHook
      wasm-pack
      wasm-bindgen-cli_0_2_108
      binaryen
      lld
    ];

    buildPhase = ''
      runHook preBuild

      mkdir --parents $out/pkg

      wasm-pack build --out-dir $out/pkg --target no-modules --no-default-features --features "wasm,elgamal,frost,gg18,musig2"

      runHook postBuild
    '';

    dontCargoInstall = true;
    # Skip tests as they are ran in the main package
    doCheck = false;
  };
in
# rustPlatform.buildRustPackage (finalAttrs: rec {
rustPlatform.buildRustPackage rec {
  inherit pname version src cargoLock;

  name = "${pname}-${version}";

  checkFlags = [
    # Skip tests that do involve a (physical) card
    "--skip=card"
  ];

  nativeBuildInputs = [
    protobuf
    pkg-config
    pcsclite
  ];

  fixupPhase = if wasm then ''
    cp --recursive ${wasmModules.out}/pkg $out/pkg
  '' else "";

  buildInputs = [
    pcsclite
    pkg-config
  ];
}
