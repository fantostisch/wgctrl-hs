module Network.WireGuard.Ctrl.Client (Client (..)) where

import Data.Text (Text)
import Network.WireGuard.Ctrl.Config (Config)
import Network.WireGuard.Ctrl.Device (Device)

data Client = Client
  { device :: Text -> IO Device,
    configureDevice :: Text -> Config -> IO (),
    close :: IO ()
  }
