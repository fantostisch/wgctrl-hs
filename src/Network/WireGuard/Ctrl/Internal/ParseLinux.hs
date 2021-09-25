module Network.WireGuard.Ctrl.Internal.ParseLinux
  ( parseDevice,
  )
where

import Crypto.Error (throwCryptoError)
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Data.ByteString as BS
import Data.Either (fromRight)
import Data.Function ((&))
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import Data.Serialize.Get (runGet)
import Data.Text.Encoding (decodeUtf8)
import Network.WireGuard.Ctrl.Device (Device (..), DeviceType (LinuxKernel))
import qualified Network.WireGuard.Ctrl.Internal.Const as Const
import Network.WireGuard.Ctrl.Internal.Utils
import System.Linux.Netlink (Attributes)
import System.Linux.Netlink.Helpers

parseDevice :: NonEmpty Attributes -> Device
parseDevice (m :| _) = parseDeviceLoop m

-- this function can throw multiple exceptions: CryptoFailable PublicKey,
-- CryptoFailable SecretKey, UnicodeException
parseDeviceLoop :: Attributes -> Device
parseDeviceLoop attrs =
  let getAttr typ =
        Map.lookup (fromEnum typ) attrs
          & fromJustNote ("Missing " ++ show typ)
      nameBytes = getAttr Const.DeviceAIfname
   in Device
        { name =
            nameBytes
              & BS.stripSuffix (BS.singleton 0)
              & fromMaybe nameBytes
              & decodeUtf8,
          deviceType = LinuxKernel,
          privateKey =
            getAttr Const.DeviceAPrivateKey
              & Curve25519.secretKey
              & throwCryptoError,
          publicKey =
            getAttr Const.DeviceAPublicKey
              & Curve25519.publicKey
              & throwCryptoError,
          listenPort =
            getAttr Const.DeviceAListenPort
              & runGet g16
              & fromRight (error "unable to parse listen port"),
          firewallMark =
            getAttr Const.DeviceAFwmark
              & runGet g32
              & fromRight (error "unable to parse firewall mark")
        }
