{
  lib,
  fetchurl,
  stdenv,
  stdenvNoCC,
  autoPatchelfHook,
}:

let
  version = "0.75.0";
  # Official release binaries, pinned independently until nixpkgs catches up.
  targets = {
    aarch64-darwin = {
      triple = "aarch64-apple-darwin";
      sha256 = "7f33f113b193900600b54951c306137ad7e04346adebaa14283c752b7673c7d0";
    };
    x86_64-darwin = {
      triple = "x86_64-apple-darwin";
      sha256 = "f460e92a820752a89be06eff67b888227e4dbaf99e05adbb36dd027ceb49823e";
    };
    aarch64-linux = {
      triple = "aarch64-unknown-linux-gnu";
      sha256 = "c5d2142077ab09b03829cf5a03c214eab761e26a440b964858f58950db93cd00";
    };
    x86_64-linux = {
      triple = "x86_64-unknown-linux-gnu";
      sha256 = "2f883269824d85f96a75fb8788f6c31619e60d2c0865e93402d2f347461054fa";
    };
  };
  target = targets.${stdenvNoCC.hostPlatform.system};
  license = fetchurl {
    url = "https://raw.githubusercontent.com/nolabs-ai/nono/v${version}/LICENSE";
    sha256 = "7310e9389f298b89bb2f90ac4b6081ed5b6a1c4a7b8547df5d52966a57cb0929";
  };
in
stdenvNoCC.mkDerivation {
  pname = "nono";
  inherit version;

  src = fetchurl {
    url = "https://github.com/nolabs-ai/nono/releases/download/v${version}/nono-v${version}-${target.triple}.tar.gz";
    inherit (target) sha256;
  };

  nativeBuildInputs = lib.optionals stdenvNoCC.hostPlatform.isLinux [ autoPatchelfHook ];
  buildInputs = lib.optionals stdenvNoCC.hostPlatform.isLinux [ stdenv.cc.cc.lib ];
  dontUnpack = true;
  dontStrip = true;

  installPhase = ''
    runHook preInstall
    tar -xzf "$src" nono
    install -Dm755 nono "$out/bin/nono"
    install -Dm644 ${license} "$out/share/licenses/nono/LICENSE"
    runHook postInstall
  '';

  doInstallCheck = stdenvNoCC.buildPlatform.canExecute stdenvNoCC.hostPlatform;
  installCheckPhase = ''
    runHook preInstallCheck
    test "$("$out/bin/nono" --version)" = "nono ${version}"
    runHook postInstallCheck
  '';

  meta = {
    description = "Kernel-enforced sandbox for AI agents";
    homepage = "https://github.com/nolabs-ai/nono";
    license = lib.licenses.asl20;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    mainProgram = "nono";
    platforms = builtins.attrNames targets;
  };
}
