# WireGuard Control Haskell (wgctrl-hs)

Enables control of WireGuard Linux kernel module using the [WireGuard Netlink API](https://git.zx2c4.com/WireGuard/tree/src/uapi/wireguard.h). Supports configuring a WireGuard device and retrieving basic information, but does not yet support retrieving peers from a WireGuard device. Implementation based on [wgctrl-go](https://github.com/WireGuard/wgctrl-go). Until batching is implemented, changing, adding or removing a lot of peers in 1 call will fail. [Example usage](app/Main.hs).

## Permissions [(source)](https://github.com/gluxon/wireguard-uapi-rs/blob/develop/README.md)

Compiled binaries need the `CAP_NET_ADMIN` capability to read network interfaces. If you're getting an access error while using this library, make sure the compiled executable has that permission. If you trust your compiled binary, one way to grant it is:

```sh
sudo setcap CAP_NET_ADMIN=+eip ./my-compiled-binary
```

## Related projects

* [wgctrl-go](https://github.com/WireGuard/wgctrl-go) enables control of WireGuard devices on multiple platforms.
* [wireguard-uapi-rs](https://github.com/gluxon/wireguard-uapi-rs) implements the WireGuard Netlink API in Rust for Linux.

## Development

### Building and running

Build on every change:

```sh
stack build --fast --file-watch
```

Running Main.hs example:

```sh
stack build --fast --copy-bins --local-bin-path=. wgctrl-hs &&
  sudo setcap cap_net_admin=ep ./wgctrl-hs &&
  ./wgctrl-hs
```

Running Main.hs with stack traces:
```sh
stack build --fast --profile --copy-bins --local-bin-path=. wgctrl-hs &&
  sudo setcap cap_net_admin=ep ./wgctrl-hs &&
  ./wgctrl-hs +RTS -xc -RTS
```

### Testing

```sh
stack test
```

### Formatting

Please format all code using [ormolu](https://github.com/tweag/ormolu) and keep lines below 90 characters.

## License

**License**: AGPL-3.0-or-later

```
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
