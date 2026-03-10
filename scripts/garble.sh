#!/bin/sh
# Wrapper script for GoReleaser to invoke garble with obfuscation flags.
# GoReleaser calls: <tool> build [flags] [ldflags] [main]
# garble needs its flags BEFORE the "build" subcommand, which GoReleaser
# can't express natively — hence this wrapper.
exec garble -literals -seed=random "$@"
