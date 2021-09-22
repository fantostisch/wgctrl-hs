module Network.WireGuard.Ctrl
  ( makeClient,
  )
where

import Network.WireGuard.Ctrl.Client (Client)
import Network.WireGuard.Ctrl.Internal.ClientLinux

makeClient :: IO Client
makeClient = makeLinuxClient
