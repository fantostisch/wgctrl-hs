module Network.WireGuard.Ctrl.Types
  ( generatePrivateKey,
    publicKey,
  )
where

import qualified Crypto.PubKey.Curve25519 as Curve25519
import Crypto.Random.Types (MonadRandom)

generatePrivateKey :: MonadRandom m => m Curve25519.SecretKey
generatePrivateKey = Curve25519.generateSecretKey

publicKey :: Curve25519.SecretKey -> Curve25519.PublicKey
publicKey = Curve25519.toPublic
