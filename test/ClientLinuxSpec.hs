{-# LANGUAGE OverloadedStrings #-}

module ClientLinuxSpec (spec) where

import Crypto.Error (throwCryptoError)
import qualified Crypto.PubKey.Curve25519 as Curve25519
import Data.Bifunctor (first)
import Data.Bits ((.|.))
import qualified Data.ByteArray as BA
import Data.ByteArray.Sized (sizedByteArray)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import Data.Either.Combinators (fromRight')
import Data.Functor ((<&>))
import qualified Data.Map.Strict as Map
import Data.Maybe (fromJust)
import Data.Serialize (runPut)
import qualified Data.Serialize as Serialize
import Data.Word
import Network.Socket (Family (AF_INET), packFamily)
import Network.WireGuard.Ctrl.Config
import Network.WireGuard.Ctrl.Internal.ClientLinux (configAttrs)
import qualified Network.WireGuard.Ctrl.Internal.Const as Const
import Network.WireGuard.Ctrl.PeerConfig
import System.Linux.Netlink (putAttributes)
import System.Linux.Netlink.Helpers
import Test.Hspec

hexToPublicKey :: BS.ByteString -> Curve25519.PublicKey
hexToPublicKey hex =
  throwCryptoError $ Curve25519.publicKey $ fromRight' $ Base16.decode hex

hexToPresharedKey :: BS.ByteString -> PresharedKey
hexToPresharedKey hex =
  fromJust $ sizedByteArray $ BA.convert $ fromRight' $ Base16.decode hex

--todo: test on architectures with different endianness
spec :: Spec
spec = do
  describe "ClientLinux" $ do
    it "can convert Config to Netlink attributes" $
      do
        let privateKey = "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
        actual <-
          configAttrs
            "wg0"
            Config
              { privateKey =
                  Just $
                    throwCryptoError $
                      Curve25519.secretKey $ fromRight' $ Base16.decode privateKey,
                listenPort = Just 12912,
                firewallMark = Just 0,
                replacePeers = True,
                peers =
                  [ {--todo (peerConfig (hexToPublicKey "b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"))
                         { presharedKey = Just $ hexToPresharedKey "188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52",
                           endpoint = Just $ Endpoint "abcd:23::33" 51820,
                           persistentKeepAliveIntervalSeconds = Nothing,
                           replaceAllowedIPs = True,
                           allowedIPs = ["192.168.4.4/32"]
                       }, --}
                    (peerConfig (hexToPublicKey "58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"))
                      { updateOnly = True,
                        endpoint = Just $ Endpoint "182.122.22.19" 3233,
                        persistentKeepAliveIntervalSeconds = Just 111,
                        replaceAllowedIPs = True,
                        allowedIPs = ["192.168.4.6/32"]
                      },
                    {--todo  (peerConfig (hexToPublicKey "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58"))
                        { endpoint = Just $ Endpoint "5.152.198.39" 51820,
                          persistentKeepAliveIntervalSeconds = Nothing,
                          replaceAllowedIPs = True,
                          allowedIPs = ["192.168.4.10/32", "192.168.4.11/32"]
                        }, --}
                    (peerConfig (hexToPublicKey "e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c"))
                      { remove = True
                      }
                  ]
              }
        let expected =
              [ (fromEnum Const.DeviceAIfname, "wg0\0"),
                ( fromEnum Const.DeviceAPrivateKey,
                  fromRight' $ Base16.decode privateKey
                ),
                (fromEnum Const.DeviceAListenPort, runPut $ p16 12912),
                (fromEnum Const.DeviceAFwmark, runPut $p32 0),
                (fromEnum Const.DeviceAFlags, runPut $p32 Const.deviceFReplacePeers),
                ( fromEnum Const.DeviceAPeers .|. fromIntegral Const.nested,
                  runPut . putAttributes $
                    Map.fromList
                      [ ( fromIntegral $ Const.nested .|. 0,
                          runPut . putAttributes $
                            Map.fromList
                              [ ( fromEnum Const.PeerAPublicKey,
                                  fromRight' $ Base16.decode "58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"
                                ),
                                ( fromEnum Const.PeerAFlags,
                                  runPut $p32 ((Const.peerFReplaceAllowedips .|. Const.peerFUpdateOnly) :: Word32)
                                ),
                                ( fromEnum Const.PeerAEndpoint,
                                  runPut $ do
                                    Serialize.putWord16le (fromIntegral (packFamily AF_INET))
                                    Serialize.putWord16be 3233
                                    Serialize.putWord32be 0xB67A1613 -- 182.122.22.19
                                    mapM_ p8 [0, 0, 0, 0, 0, 0, 0, 0]
                                ),
                                (fromEnum Const.PeerAPersistentKeepaliveInterval, runPut $ p16 111),
                                ( fromEnum Const.PeerAAllowedips .|. fromIntegral Const.nested,
                                  runPut . putAttributes $
                                    Map.fromList
                                      [ ( 0 .|. fromIntegral Const.nested,
                                          runPut . putAttributes $
                                            Map.fromList
                                              [ ( fromEnum Const.AllowedipAFamily,
                                                  runPut $ p16 (fromIntegral $ packFamily AF_INET)
                                                ),
                                                (fromEnum Const.AllowedipAIpaddr, runPut $ Serialize.putWord32be 0xC0A80406), -- 192,168,4,6
                                                (fromEnum Const.AllowedipACidrMask, runPut $ p8 32)
                                              ]
                                        )
                                      ]
                                )
                              ]
                        ),
                        ( fromIntegral $ Const.nested .|. 1,
                          runPut . putAttributes $
                            Map.fromList
                              [ (fromEnum Const.PeerAPublicKey, fromRight' $ Base16.decode "e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c"),
                                (fromEnum Const.PeerAFlags, runPut $ p32 Const.peerFRemoveMe)
                              ]
                        )
                      ]
                )
              ]
                <&> first fromIntegral
        actual `shouldBe` Map.fromList expected
