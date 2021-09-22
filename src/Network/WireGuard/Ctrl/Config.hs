module Network.WireGuard.Ctrl.Config
  ( Config (..),
    config,
  )
where

{- See https://github.com/WireGuard/wgctrl-go/blob/be3cfad7ce0576d1cc885b0f912fa849b7600857/wgtypes/types.go
for documentation on types and functions. -}

import qualified Crypto.PubKey.Curve25519 as Curve25519
import Data.Word (Word16, Word32)
import Network.WireGuard.Ctrl.PeerConfig

data Config = Config
  { privateKey :: Maybe Curve25519.SecretKey,
    listenPort :: Maybe Word16,
    firewallMark :: Maybe Word32,
    replacePeers :: Bool,
    peers :: [PeerConfig]
  }

-- Create Config with default values
config :: Config
config =
  Config
    { privateKey = Nothing,
      listenPort = Nothing,
      firewallMark = Nothing,
      replacePeers = False,
      peers = []
    }
