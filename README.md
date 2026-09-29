# ztr-ps

A reimplementation of the 3DS `ps` sysmodule written in zig.

Note that this one is not a 1:1, unimplemented and/or removed commands in the latest version are directly 
not implemented in the sysmodule itself.

## Building

The only dependency is `zig 0.16.0` (already available in the repo flake if you use nix)

Run `zig build`; it'll download dependencies and build `zitrus` tools first, afterwards rebuilds are instantaneous.

You should see `ps.cxi` in `zig-out/bin` alongside `ps.elf`.

## Running (Luma3DS)

Copy `ps.cxi` to `/luma/sysmodules/0004013000003102.cxi` in your sd card.
  
...
  
Profit?

## Credits

All credits go to `3dbrew` and `GBATEK` as I could not do this without all the available documentation.
