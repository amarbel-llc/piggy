# Merge the .profraw files the coverage VM lanes shipped in their $out
# and report line/function/region coverage over the instrumented Rust
# binaries with the LLVM tools that match nixpkgs' rustc (a profdata
# from one LLVM version is unreadable by another).
#
# Outputs:
#   $out/report.txt    llvm-cov report (per-file table + TOTAL line)
#   $out/summary.json  llvm-cov export --summary-only
#   $out/lcov.info     lcov tracefile for editors / genhtml
#   $out/merged.profdata
#
# Only piggy's own crates are counted: vendored dependencies (under the
# cargo vendor dir), the rust std sources, and vendor/ are ignored.
{
  pkgs,
  # The vm-piggy-*-cov test derivations (each has $out/coverage/*.profraw).
  tests,
  # Instrumented, unstripped binaries the profiles were produced by.
  objects,
}:
let
  llvm = pkgs.rustc.llvmPackages.llvm;
  objectFlags = pkgs.lib.concatMapStringsSep " " (o: "-object ${o}") objects;
  ignore = "'(cargo-vendor|/rustc/|\\.cargo/registry|/vendor/)'";
in
pkgs.runCommand "piggy-coverage-report"
  {
    nativeBuildInputs = [ llvm ];
    inherit tests;
  }
  ''
    mkdir -p "$out"
    profraws=()
    for t in $tests; do
      for f in "$t"/coverage/*.profraw; do
        [ -e "$f" ] && profraws+=("$f")
      done
    done
    echo "merging ''${#profraws[@]} profraw files from ${toString (builtins.length tests)} lanes" >&2
    [ "''${#profraws[@]}" -gt 0 ] || { echo "no .profraw files found in the coverage lanes" >&2; exit 1; }

    llvm-profdata merge -sparse "''${profraws[@]}" -o "$out/merged.profdata"

    llvm-cov report ${objectFlags} \
      --instr-profile="$out/merged.profdata" \
      --ignore-filename-regex=${ignore} \
      > "$out/report.txt"
    llvm-cov export ${objectFlags} \
      --instr-profile="$out/merged.profdata" \
      --ignore-filename-regex=${ignore} \
      --summary-only --format=text > "$out/summary.json"
    llvm-cov export ${objectFlags} \
      --instr-profile="$out/merged.profdata" \
      --ignore-filename-regex=${ignore} \
      --format=lcov > "$out/lcov.info"

    tail -n 1 "$out/report.txt" >&2
  ''
