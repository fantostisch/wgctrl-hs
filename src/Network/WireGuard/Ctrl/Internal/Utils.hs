module Network.WireGuard.Ctrl.Internal.Utils where

fromJustNote :: String -> Maybe a -> a
fromJustNote _ (Just a) = a
fromJustNote m Nothing = error m
