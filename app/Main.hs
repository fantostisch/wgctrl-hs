{-# LANGUAGE OverloadedStrings #-}

module Main where

import Crypto.Error (throwCryptoError)
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Data.ByteString.Base16 as Base16
import Data.Either.Combinators (fromRight')
import qualified Network.WireGuard.Ctrl as Ctrl
import qualified Network.WireGuard.Ctrl.Client as Client
import Network.WireGuard.Ctrl.Config
import Network.WireGuard.Ctrl.PeerConfig
import qualified Network.WireGuard.Ctrl.Types as Types
import Text.Pretty.Simple (pPrint)

main :: IO ()
main = do
  let device = "wg0"
  client <- Ctrl.makeClient
  serverPrivateKey <- Types.generatePrivateKey
  let peerPublicKey =
        throwCryptoError $
          Curve25519.publicKey $
            fromRight' $
              Base16.decode "58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"
  Client.configureDevice
    client
    device
    ( config
        { privateKey = Just serverPrivateKey,
          peers =
            [ ( (peerConfig peerPublicKey)
                  { replaceAllowedIPs = True,
                    allowedIPs = ["10.0.0.3/32", "2001:0DB8:AC10:FE01::/128"]
                  }
              )
            ]
        }
    )
  deviceInfo <- Client.device client device
  Client.close client
  pPrint deviceInfo
  putStrLn "Done"
