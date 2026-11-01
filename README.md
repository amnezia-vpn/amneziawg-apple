# [WireGuard](https://www.wireguard.com/) for iOS and macOS

This project contains an application for iOS and for macOS, as well as many components shared between the two of them. You may toggle between the two platforms by selecting the target from within Xcode.

## Building

- Clone this repo:

```
$ git clone https://git.zx2c4.com/wireguard-apple
$ cd wireguard-apple
```

- Rename and populate developer team ID file:

```
$ cp Sources/WireGuardApp/Config/Developer.xcconfig.template Sources/WireGuardApp/Config/Developer.xcconfig
$ vim Sources/WireGuardApp/Config/Developer.xcconfig
```

- Install swiftlint and go 1.19:

```
$ brew install swiftlint go
```

- Open project in Xcode:

```
$ open WireGuard.xcodeproj
```

- Flip switches, press buttons, and make whirling noises until Xcode builds it.

## WireGuardKit integration

1. Open your Xcode project and add the Swift package with the following URL:
   
   ```
   https://git.zx2c4.com/wireguard-apple
   ```
   
2. `WireGuardKit` links against `wireguard-go-bridge` library, but it cannot build it automatically
   due to Swift package manager limitations. So it needs a little help from a developer. 
   Please follow the instructions below to create a build target(s) for `wireguard-go-bridge`.
   
   - In Xcode, click File -> New -> Target. Switch to "Other" tab and choose "External Build 
     System".
   - Type in `WireGuardGoBridge<PLATFORM>` under the "Product name", replacing the `<PLATFORM>` 
     placeholder with the name of the platform. For example, when targeting macOS use `macOS`, or 
     when targeting iOS use `iOS`.
     Make sure the build tool is set to: `/usr/bin/make` (default).
   - In the appeared "Info" tab of a newly created target, type in the "Directory" path under 
     the "External Build Tool Configuration":
     
     ```
     ${BUILD_DIR%Build/*}SourcePackages/checkouts/wireguard-apple/Sources/WireGuardKitGo
     ```
     
   - Switch to "Build Settings" and find `SDKROOT`.
     Type in `macosx` if you target macOS, or type in `iphoneos` if you target iOS.
   
3. Go to Xcode project settings and locate your network extension target and switch to 
   "Build Phases" tab.
   
   - Locate "Dependencies" section and hit "+" to add `WireGuardGoBridge<PLATFORM>` replacing 
     the `<PLATFORM>` placeholder with the name of platform matching the network extension 
     deployment target (i.e macOS or iOS).
     
   - Locate the "Link with binary libraries" section and hit "+" to add `WireGuardKit`.
   
4. In Xcode project settings, locate your main bundle app and switch to "Build Phases" tab. 
   Locate the "Link with binary libraries" section and hit "+" to add `WireGuardKit`.
   
5. iOS only: Locate Bitcode settings under your application target, Build settings -> Enable Bitcode, 
   change the corresponding value to "No".
   
Note that if you ship your app for both iOS and macOS, make sure to repeat the steps 2-4 twice, 
once per platform.

## DNS SRV endpoint discovery

DNS SRV discovery is opt-in. A normal `Endpoint = vpn.example.com:51820` keeps
its existing fixed-port behavior. To discover both the hostname and UDP port,
use an explicit, fully qualified SRV owner name:

```ini
[Peer]
PublicKey = <server public key>
Endpoint = srv://_wireguard._udp.vpn.example.com
AllowedIPs = 192.168.10.0/24
```

For example, publish these DNS records (the addresses are documentation examples):

```dns
_wireguard._udp.vpn.example.com. 300 IN SRV 10 10 9783 endpoint.example.com.
endpoint.example.com.           300 IN A   192.0.2.1
```

The client uses the system DNS-SD resolver and then resolves the selected target's
A/AAAA addresses using the existing address resolver. Lower numeric priorities
are tried first; records of equal priority are selected by weight. A failed
target address lookup tries the next record. A target of `.` means the service
is unavailable. Missing or invalid SRV answers fail discovery rather than
silently guessing a port. This does not add connection-level health checks or
handshake-based failover between SRV targets.

SRV endpoints are resolved at startup and refreshed on satisfied network-path
updates and approximately every 60 seconds while the backend is running. System
DNS caching and record TTLs still apply. A changed port updates the peer without
restarting the tunnel; a changed IP also updates the tunnel's excluded routes.
Transient refresh errors retain the last working endpoint. Unchanged DNS answers
do not overwrite endpoint roaming learned by the backend. The configured SRV URL
is preserved when exporting the tunnel.

DNS must be reachable both before connecting and when refreshing. In particular,
a DNS server reachable only through an already broken tunnel cannot bootstrap
discovery. SRV only selects an endpoint: the configured WireGuard peer key still
authenticates it, and the server must use compatible protocol settings. These
SRV URLs are an app extension and are not understood by stock `wg-quick`.

On macOS, `python3 Scripts/test-srv.py` runs the resolver/model unit tests without
building the Go backend or requiring signing credentials.

## MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
