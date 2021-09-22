module Network.WireGuard.Ctrl.Client (Client (..)) where

import Data.Text (Text)
import Network.WireGuard.Ctrl.Config (Config)

data Client = Client
  { configureDevice :: Text -> Config -> IO (),
    close :: IO ()
  }
