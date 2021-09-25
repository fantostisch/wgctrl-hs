module Network.WireGuard.Ctrl.Internal.Const where

import Data.Bits (shift, (.|.))
import Data.Word (Word16, Word32, Word8)
import System.Linux.Netlink.Constants (fNLM_F_MATCH, fNLM_F_ROOT)

nested :: Word16
nested = 0x8000

--todo: should be in netlink-hs
fNLM_F_DUMP :: Word16
fNLM_F_DUMP = fNLM_F_ROOT .|. fNLM_F_MATCH

-- Based on https://github.com/WireGuard/wgctrl-go/blob/2a9a29e81620f94626729d3c1b49ce184395dfd0/internal/wglinux/internal/wgh/const.go

genlName :: String
genlName = "wireguard"

genlVersion :: Word8
genlVersion = 1

keyLen :: Int
keyLen = 32

cmdMax :: Int
cmdMax = fromEnum CmdMax - 1

deviceAMax :: Int
deviceAMax = fromEnum DeviceALast - 1

peerAMax :: Int
peerAMax = fromEnum PeerALast - 1

allowedipAMax :: Int
allowedipAMax = fromEnum AllowedipALast - 1

data WGCmd
  = CmdGetDevice
  | CmdSetDevice
  | CmdMax
  deriving (Enum)

deviceFReplacePeers :: Word32
deviceFReplacePeers = (1 :: Word32) `shift` 0

deviceFAll :: Word32
deviceFAll = deviceFReplacePeers

peerFRemoveMe :: Word32
peerFRemoveMe = (1 :: Word32) `shift` 0

peerFReplaceAllowedips :: Word32
peerFReplaceAllowedips = (1 :: Word32) `shift` 1

peerFUpdateOnly :: Word32
peerFUpdateOnly = (1 :: Word32) `shift` 2

data WGDeviceAttribute
  = DeviceAUnspec
  | DeviceAIfindex
  | DeviceAIfname
  | DeviceAPrivateKey
  | DeviceAPublicKey
  | DeviceAFlags
  | DeviceAListenPort
  | DeviceAFwmark
  | DeviceAPeers
  | DeviceALast
  deriving (Enum, Show)

data WGPeerAttribute
  = PeerAUnspec
  | PeerAPublicKey
  | PeerAPresharedKey
  | PeerAFlags
  | PeerAEndpoint
  | PeerAPersistentKeepaliveInterval
  | PeerALastHandshakeTime
  | PeerARxBytes
  | PeerATxBytes
  | PeerAAllowedips
  | PeerAProtocolVersion
  | PeerALast
  deriving (Enum, Show)

data WGAllowedipAttribute
  = AllowedipAUnspec
  | AllowedipAFamily
  | AllowedipAIpaddr
  | AllowedipACidrMask
  | AllowedipALast
  deriving (Enum, Show)
