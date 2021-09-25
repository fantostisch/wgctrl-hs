{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}

module Network.WireGuard.Ctrl.Internal.ClientLinux
  ( makeLinuxClient,
    configAttrs,
  )
where

import Control.Exception (throwIO)
import Data.Atomics.Counter (AtomicCounter)
import qualified Data.Atomics.Counter as Counter
import Data.Bifunctor (first, second)
import qualified Data.Bifunctor as Bifunctor
import Data.Bits ((.|.))
import Data.ByteArray (convert, singleton)
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe (unsafePackCStringFinalizer)
import Data.Either (fromRight, partitionEithers)
import Data.Function ((&))
import Data.Functor ((<&>))
import Data.IP
import qualified Data.IP as IP
import qualified Data.List as List
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NonEmpty
import qualified Data.Map.Strict as Map
import Data.Maybe (catMaybes)
import Data.Serialize (putByteString, runPut)
import qualified Data.Serialize as Serialize
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Word (Word16, Word32)
import Foreign.C (Errno (..), errnoToIOError)
import Foreign.Marshal.Alloc
import Foreign.Ptr (Ptr, castPtr)
import GHC.Base (failIO)
import Network.Socket (Family (AF_INET, AF_INET6), SockAddr (..), packFamily)
import Network.Socket.Address (pokeSocketAddress, sizeOfSocketAddress)
import Network.WireGuard.Ctrl.Client
import Network.WireGuard.Ctrl.Config (Config)
import qualified Network.WireGuard.Ctrl.Config as Config
import Network.WireGuard.Ctrl.Device (Device)
import Network.WireGuard.Ctrl.Internal.Const (WGCmd, fNLM_F_DUMP)
import qualified Network.WireGuard.Ctrl.Internal.Const as Const
import Network.WireGuard.Ctrl.Internal.ParseLinux
import Network.WireGuard.Ctrl.PeerConfig as PeerConfig
import System.Linux.Netlink
import System.Linux.Netlink.Constants (fNLM_F_ACK, fNLM_F_MULTI, fNLM_F_REQUEST)
import System.Linux.Netlink.GeNetlink
import qualified System.Linux.Netlink.GeNetlink as GeNetLink
import System.Linux.Netlink.GeNetlink.Control (CtrlAttribute (CTRL_ATTR_FAMILY_ID))
import qualified System.Linux.Netlink.GeNetlink.Control as Control
import System.Linux.Netlink.Helpers

data ClientLinux = ClientLinux
  { socket :: NetlinkSocket,
    pid :: Word32,
    seqNum :: AtomicCounter,
    familyID :: Word16
  }

clientLinux :: ClientLinux -> Client
clientLinux c =
  Client
    { device = linuxDevice c,
      configureDevice = configureLinuxDevice c,
      close = closeLinuxClient c
    }

makeLinuxClient :: IO Client
makeLinuxClient = GeNetLink.makeSocket >>= initClient <&> clientLinux

--todo: netlink-hs getFamilyId should return PID or allow to specify PID
--todo: netlink-hs should handle sequence number and PID
getFamilyIdAndPID :: NetlinkSocket -> String -> IO (Word32, Maybe Word16)
getFamilyIdAndPID s n = do
  packet <- queryOne s (Control.familyIdRequest n)
  let ctrl = Control.ctrlPacketFromGenl packet
  pure
    (packet & packetHeader & messagePID, ctrl >>= getIdFromList . Control.ctrlAttributes)
  where
    getIdFromList (CTRL_ATTR_FAMILY_ID x : _) = Just x
    getIdFromList (_ : xs) = getIdFromList xs
    getIdFromList [] = Nothing

initClient :: NetlinkSocket -> IO ClientLinux
initClient s = do
  (pid, mFamID) <- getFamilyIdAndPID s Const.genlName
  {-- familyIdRequest in netlink-hs uses 33 as sequence number --}
  seqNumCounter <- Counter.newCounter 33
  case mFamID of
    Just famID ->
      pure $
        ClientLinux
          { socket = s,
            pid = pid,
            seqNum = seqNumCounter,
            familyID = famID
          }
    Nothing -> fail "unable to get wireguard family id"

closeLinuxClient :: ClientLinux -> IO ()
closeLinuxClient c = closeSocket $ socket c

{- todo: batching, see https://github.com/WireGuard/wgctrl-go/blob/4253848d036c7873fa1fbdfbc2d10ff15dc81ccb/internal/wglinux/client_linux.go#L122
    and https://git.zx2c4.com/wireguard-linux/tree/include/uapi/linux/wireguard.h -}
configureLinuxDevice :: ClientLinux -> Text -> Config -> IO ()
configureLinuxDevice c name cfg =
  do
    attrs <- configAttrs name cfg
    r <- execute c Const.CmdSetDevice (fNLM_F_REQUEST .|. fNLM_F_ACK) attrs
    case r of
      Right _ -> pure ()
      Left (Errno 0) -> pure ()
      Left errno ->
        throwIO $
          errnoToIOError errMsg errno Nothing Nothing
        where
          errMsg = "error while configuring wireguard device " ++ T.unpack name

nameAttr :: Text -> (Int, BS.ByteString)
nameAttr name = (fromEnum Const.DeviceAIfname, encodeUtf8 name <> singleton 0)

linuxDevice :: ClientLinux -> Text -> IO Device
linuxDevice c name = do
  let attrs = Map.fromList [nameAttr name]
  r <- execute c Const.CmdGetDevice (fNLM_F_REQUEST .|. fNLM_F_DUMP .|. fNLM_F_MULTI) attrs
  case r of
    Right m -> pure $ parseDevice (m <&> snd)
    Left errno ->
      throwIO $
        errnoToIOError errMsg errno Nothing Nothing
      where
        errMsg = "error while retrieving information from wireguard device " ++ T.unpack name

--todo: nested support should be in the netlink library
nested :: Word16 -> (a -> IO Attributes) -> [a] -> IO (Word16, Maybe BS.ByteString)
nested typ f list =
  if not (null list)
    then do
      encodedItems <-
        mapM (\p -> f p <&> (runPut . putAttributes)) list
          <&> zip ([0 ..] <&> (.|. Const.nested) <&> fromIntegral)
      pure (nestedTyp, Just $ (runPut . putAttributes) $ Map.fromList encodedItems)
    else pure (nestedTyp, Nothing)
  where
    nestedTyp = typ .|. Const.nested

configAttrs :: Text -> Config -> IO Attributes
configAttrs name cfg = do
  encodedPeers <-
    nested (fromIntegral $ fromEnum Const.DeviceAPeers) encodePeer (Config.peers cfg)
  pure $
    Map.fromList $
      catMaybes $
        [ Just `second` nameAttr name,
          (fromEnum Const.DeviceAPrivateKey, Config.privateKey cfg <&> convert),
          (fromEnum Const.DeviceAListenPort, Config.listenPort cfg <&> (runPut . p16)),
          (fromEnum Const.DeviceAFwmark, Config.firewallMark cfg <&> (runPut . p32)),
          ( fromEnum Const.DeviceAFlags,
            if Config.replacePeers cfg
              then Just $ runPut $ p32 Const.deviceFReplacePeers
              else Nothing
          ),
          encodedPeers & first fromIntegral
        ]
          <&> (\(typ, mv) -> mv <&> (typ,))

encodePeer :: PeerConfig -> IO Attributes
encodePeer peer = do
  encodedSA <- PeerConfig.endpoint peer <&> encodeSockaddr & sequenceA
  encodedAIPS <-
    nested
      (fromIntegral $ fromEnum Const.PeerAAllowedips)
      (pure . encodeAllowedIP)
      (PeerConfig.allowedIPs peer)
  let flagList =
        [ (PeerConfig.remove peer, Const.peerFRemoveMe),
          (PeerConfig.replaceAllowedIPs peer, Const.peerFReplaceAllowedips),
          (PeerConfig.updateOnly peer, Const.peerFUpdateOnly)
        ]
  pure $
    Map.fromList $
      catMaybes $
        [ (fromEnum Const.PeerAPublicKey, Just $ convert $ PeerConfig.publicKey peer),
          ( fromEnum Const.PeerAFlags,
            if not (null flagList)
              then
                Just $
                  runPut $
                    p32 $
                      (List.filter fst flagList <&> snd) & List.foldl' (.|.) 0
              else Nothing
          ),
          (fromEnum Const.PeerAPresharedKey, PeerConfig.presharedKey peer <&> convert),
          (fromEnum Const.PeerAEndpoint, encodedSA),
          ( fromEnum Const.PeerAPersistentKeepaliveInterval,
            PeerConfig.persistentKeepAliveIntervalSeconds peer
              <&> (runPut . p16)
          ),
          encodedAIPS & first fromIntegral
        ]
          <&> (\(typ, mv) -> mv <&> (typ,))

encodeSockaddr :: Endpoint -> IO BS.ByteString
encodeSockaddr ep =
  withSockAddr sa (\p l -> unsafePackCStringFinalizer (castPtr p) l (pure ()))
  where
    sa = endpointToSockAddr ep

endpointToSockAddr :: Endpoint -> SockAddr
endpointToSockAddr (Endpoint ip port) = toSockAddr (ip, fromIntegral port)

-- | Use a 'SockAddr' with a function requiring a pointer to a
-- 'SockAddr' and the length of that 'SockAddr'.
-- Based on withSockAddr from https://hackage.haskell.org/package/network-3.1.2.2/docs/src/Network.Socket.Types.html
withSockAddr :: SockAddr -> (Ptr SockAddr -> Int -> IO a) -> IO a
withSockAddr addr f = do
  let sz = sizeOfSocketAddress addr
  allocaBytes sz $ \p -> pokeSocketAddress p addr >> f p sz

listToAttributes :: Enum e => [(e, b)] -> Map.Map Int b
listToAttributes list = Map.fromList $ list <&> Bifunctor.first fromEnum

encodeAllowedIP :: IPRange -> Attributes
encodeAllowedIP (IPv4Range r) =
  listToAttributes
    [ (Const.AllowedipAFamily, runPut $ p16 (fromIntegral $ packFamily AF_INET)),
      (Const.AllowedipAIpaddr, runPut $ Serialize.putWord32be $ IP.fromIPv4w ip),
      (Const.AllowedipACidrMask, runPut $ p8 $ fromIntegral mask)
    ]
  where
    (ip, mask) = addrRangePair r
encodeAllowedIP (IPv6Range r) =
  listToAttributes
    [ (Const.AllowedipAFamily, runPut $ p16 (fromIntegral $ packFamily AF_INET6)),
      ( Const.AllowedipAIpaddr,
        runPut $ mapM_ (Serialize.putWord16be . fromIntegral) ipHost
      ),
      (Const.AllowedipACidrMask, runPut $ p8 $ fromIntegral mask)
    ]
  where
    (ipHost, mask) = addrRangePair r & first IP.fromIPv6

-- Based on packMessage from mdlayher/genetlink, todo: upstream to netlink?
-- packMessage packs a generic netlink Message into a netlink.Message with the
-- appropriate generic netlink family and netlink flags.
packMessage :: GenlData a -> Word16 -> Word16 -> Word32 -> Word32 -> Packet (GenlData a)
packMessage msg familyID flags seqNum pid =
  let header = Header (fromIntegral familyID) flags seqNum pid
   in (Packet {packetHeader = header, packetCustom = msg, packetAttributes = Map.empty})

execute ::
  ClientLinux ->
  WGCmd ->
  Word16 ->
  Attributes ->
  IO (Either Errno (NonEmpty (GenlData BS.ByteString, Attributes)))
execute c command flags attrs = do
  seqInt <- Counter.incrCounter 1 (seqNum c)
  let seqWord = fromIntegral seqInt --todo: does this work when seqnum overflows?
  let geHeader =
        GenlHeader
          { genlCmd = fromIntegral $ fromEnum command,
            genlVersion = Const.genlVersion
          }
      geMessage = GenlData geHeader (runPut $ putAttributes attrs)
  receivedMessages <-
    query
      (socket c)
      (packMessage geMessage (familyID c) flags seqWord (pid c))
  messages <-
    sequence $
      receivedMessages
        <&> ( \case
                Packet _ gd attrs -> pure $ Right (gd, attrs)
                ErrorMsg _ minusErrno _ -> pure $ Left $ Errno (-1 * minusErrno)
                DoneMsg _ -> failIO "Unexpected done message"
            )
  pure $ case partitionEithers messages of
    ([e], _) -> Left e
    (_, m) -> Right $ NonEmpty.fromList m

instance Convertable BS.ByteString where
  getGet _ = pure BS.empty -- Used when retrieving information from WG
  getPut = putByteString -- Used when configuring WG device
