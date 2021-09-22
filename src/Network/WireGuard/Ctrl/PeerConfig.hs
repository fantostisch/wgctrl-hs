{-# LANGUAGE DataKinds #-}

module Network.WireGuard.Ctrl.PeerConfig
  ( PeerConfig (..),
    PresharedKey,
    Endpoint (..),
    peerConfig,
  )
where

{- See https://github.com/WireGuard/wgctrl-go/blob/be3cfad7ce0576d1cc885b0f912fa849b7600857/wgtypes/types.go
for documentation on types and functions. -}

import qualified Crypto.PubKey.Curve25519 as Curve25519
import Data.ByteArray (ScrubbedBytes)
import Data.ByteArray.Sized (SizedByteArray)
import Data.IP
import Data.Word (Word16)

type PresharedKey = SizedByteArray 32 ScrubbedBytes

data Endpoint = Endpoint {ip :: IP, port :: Word16}

data PeerConfig = PeerConfig
  { publicKey :: Curve25519.PublicKey,
    remove :: Bool,
    updateOnly :: Bool,
    presharedKey :: Maybe PresharedKey,
    endpoint :: Maybe Endpoint,
    persistentKeepAliveIntervalSeconds :: Maybe Word16,
    replaceAllowedIPs :: Bool,
    allowedIPs :: [IPRange]
  }

-- Create PeerConfig with default values
peerConfig :: Curve25519.PublicKey -> PeerConfig
peerConfig publicKey =
  PeerConfig
    { publicKey = publicKey,
      remove = False,
      updateOnly = False,
      presharedKey = Nothing,
      endpoint = Nothing,
      persistentKeepAliveIntervalSeconds = Nothing,
      replaceAllowedIPs = False,
      allowedIPs = []
    }
