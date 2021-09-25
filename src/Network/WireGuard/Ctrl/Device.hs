module Network.WireGuard.Ctrl.Device
  ( Device (..),
    DeviceType (..),
  )
where

import qualified Crypto.PubKey.Curve25519 as Curve25519
import Data.Text (Text)
import Data.Word (Word16, Word32)

data DeviceType = LinuxKernel | OpenBSDKernel | Userspace
  deriving (Show)

data Device = Device
  { name :: Text,
    deviceType :: DeviceType,
    privateKey :: Curve25519.SecretKey,
    publicKey :: Curve25519.PublicKey,
    listenPort :: Word16,
    firewallMark :: Word32
  }
  deriving (Show)
