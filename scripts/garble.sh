#!/bin/sh
# Wrapper script for GoReleaser to invoke garble with obfuscation flags.
# GoReleaser calls: <tool> build [flags] [ldflags] [main]
# garble needs its flags BEFORE the "build" subcommand, which GoReleaser
# can't express natively — hence this wrapper.
#
# GOGARBLE limits obfuscation to first-party code only. Third-party
# dependencies (especially godbus/dbus and zalando/go-keyring) must NOT
# be obfuscated — garble creates duplicate type scopes that break D-Bus
# interface type assertions on Linux, causing a fatal panic.
export GOGARBLE=github.com/shiftinbits/pmux-agent
exec garble -literals -seed=random "$@"
