{
  ebpfRust,
  writeShellApplication,
}:
writeShellApplication {
  name = "rustup";

  text = ''
    if [[ $# -lt 3 || "$1" != "run" || "$2" != "nightly-2026-08-04" ]]; then
      printf 'unsupported rustup invocation:' >&2
      printf ' %q' "$@" >&2
      printf '\n' >&2
      exit 2
    fi

    shift 2
    program=$1
    shift

    case "$program" in
      cargo|rustc|rustdoc)
        ;;
      *)
        echo "unsupported nightly program: $program" >&2
        exit 2
        ;;
    esac

    # Aya removes Cargo's inherited RUSTC before starting its nested eBPF
    # build. Put the pinned nightly first so that nested Cargo also uses it.
    export PATH="${ebpfRust}/bin:$PATH"
    export RUSTC="${ebpfRust}/bin/rustc"
    export RUSTDOC="${ebpfRust}/bin/rustdoc"
    exec "${ebpfRust}/bin/$program" "$@"
  '';
}
