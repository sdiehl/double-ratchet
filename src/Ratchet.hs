{-|

An implementation of Open Whisper System's Double Ratchet Algorithm in Haskell.

The Double Ratchet algorithm is used by two parties to exchange encrypted
messages based on a shared secret key. Typically the parties will use some key
agreement protocol (such as X3DH) to agree on the shared secret key.  Following
this, the parties will use the Double Ratchet to send and receive encrypted
messages.

The parties derive new keys for every Double Ratchet message so that earlier
keys cannot be calculated from later ones. The parties also send Diffie-Hellman
public values attached to their messages. The results of Diffie-Hellman
calculations are mixed into the derived keys so that later keys cannot be
calculated from earlier ones. These properties gives some protection to earlier
or later encrypted messages in case of a compromise of a party's keys.

-}

module Ratchet (
    module Ratchet.Types
  , ratchetInitAlice
  , ratchetInitBob
  , ratchetEncrypt
  , ratchetDecrypt
  , genSharedSecret
  , generateDH
) where

import Protolude hiding (concat)

import qualified Data.HashMap.Strict as HMap
import qualified Crypto.PubKey.Curve25519 as C25519
import qualified Data.ByteArray as B
import           Data.Maybe (fromJust)
import           Data.Serialize (decode)
import           Crypto.Random (MonadRandom, getRandomBytes)

import Ratchet.Types
import Ratchet.Defaults

-- | Initialises ratchet state for Alice (the party sending the first message)
ratchetInitAlice :: MonadRandom m => SharedSecretKey
                    -> C25519.PublicKey
                    -> StateT StateRatchet m ()
ratchetInitAlice sk bobDHPublicKey = do
  state <- get
  dhs <- lift generateDH
  let dhr = B.convert bobDHPublicKey
  let dhOut = dh dhs dhr
      (rk', cks) = kdfRk (sskToRk sk) dhOut
      state' =
        state { dh_s = dhs
              , dh_r = Just dhr
              , rk   = rk'
              , ck_s = cks
              , ck_r = Nothing
              , n_s  = 0
              , n_r  = 0
              , p_n  = 0
              , mk_skipped = HMap.empty
              }
  put state'

-- | Initialises ratchet state for Bob (the party receiving the first message)
ratchetInitBob :: MonadRandom m => SharedSecretKey
                  -> DHKeyPair
                  -> StateT StateRatchet m ()
ratchetInitBob sk bobDHKeyPair = do
  state <- get
  let state' =
        state { dh_s = bobDHKeyPair
              , dh_r = Nothing
              , rk   = sskToRk sk
              , ck_r = Nothing
              , n_s  = 0
              , n_r  = 0
              , p_n  = 0
              , mk_skipped = HMap.empty
              }
  put state'

ratchetEncrypt :: MonadRandom m => PlainText
                  -> AssocData
                  -> StateT StateRatchet m (MessageHeader, Either RatchetError AEADCipherText) -- BEAUTIFY ME
ratchetEncrypt plain ad = do
  state <- get
  let (cks, mk) = kdfCk $ ck_s state
      headerVal = header (dh_s state) (p_n state) (n_s state)
      n_s'      = n_s state + 1
      state' = state {  ck_s = cks
                      , n_s  = n_s'
                     } 
      enc = encrypt mk plain $ concat ad headerVal
  put state'
  return (headerVal, enc)

ratchetDecrypt :: MonadRandom m => MessageHeader
                  -> AEADCipherText
                  -> AssocData
                  -> StateT StateRatchet m (Either RatchetError PlainText)
ratchetDecrypt mh aeadCipher ad = do
  val <- trySkippedMessageKeys mh aeadCipher ad 
  case val of
    Just plain ->
      return $ Right plain

    Nothing -> do
      state <- get
      let dhr = dh_r state
      if dhr == Nothing ||
         dh_ratchet_pub_key mh /= (B.convert $ fromJust dhr)
        then do
          skipMessageKeys $ pn_mh mh
          dhRatchet mh
          finishIt
        else finishIt

  where
    finishIt = do
      skipMessageKeys $ msg_number mh
      state <- get
      let (ckr, mk) = kdfCk $ fromJust $ ck_r state
      let state' = state {  ck_r = Just ckr
                          , n_r = n_r state + 1
                         }
      put state'
      return $ decrypt mk aeadCipher $ concat ad mh
         
trySkippedMessageKeys :: MonadRandom m => MessageHeader
                          -> AEADCipherText
                          -> AssocData
                          -> StateT StateRatchet m (Maybe PlainText)
trySkippedMessageKeys mh aeadCipher ad = do
  state <- get
  let msgMap = mk_skipped state
      key = (dh_ratchet_pub_key mh, msg_number mh)
  case HMap.lookup key msgMap of
    Nothing ->
      return Nothing

    Just mk -> do
      let msgMap' = HMap.delete key msgMap
          state'  = state { mk_skipped = msgMap' }
      put state'
      return $ rightToMaybe $ decrypt mk aeadCipher $ concat ad mh
      
skipMessageKeys :: MonadRandom m => Int -> StateT StateRatchet m (Either RatchetError ())
skipMessageKeys until = do
  state <- get
  if n_r state + (max_skip state) < until
    then return $ Left SkipMessageKeys
    else case ck_r state of
      Nothing -> return $ Right ()
      
      Just _ -> insert $ n_r state

  where
    insert :: MonadRandom m => Int -> StateT StateRatchet m (Either RatchetError ())
    insert ctr
      | ctr >= until = return $ Right ()
      | otherwise = do
          state <- get
          let ckr = fromJust $ ck_r state
              dhr = dh_r state
              nr  = ctr
              msgMap = mk_skipped state
              (ckr', mk) = kdfCk ckr
              msgMap' = HMap.insert (fromJust dhr, nr) mk msgMap
              nr' = nr + 1
              state' = state {  mk_skipped = msgMap'
                             ,  n_r        = nr'
                             ,  ck_r       = Just ckr'
                             }
          put state'
          insert $ ctr + 1
              
dhRatchet :: MonadRandom m => MessageHeader
              -> StateT StateRatchet m ()
dhRatchet mh = do
  state <- get
  let pn = n_s state
      ns = 0
      nr = 0
      dhr = dh_ratchet_pub_key mh
      (rk', ckr) = kdfRk (rk state) $
                    dh (dh_s state) dhr
  dhs <- lift generateDH
  let (rk'', cks) = kdfRk rk' $ dh dhs $ B.convert dhr
      state' = state {  dh_s = dhs
                      , rk   = rk''
                      , dh_r = Just dhr
                      , n_s  = ns
                      , n_r  = nr
                      , p_n  = pn
                      , ck_r = Just ckr
                      , ck_s = cks
                     }
  put state'

-- | Returns a new shared secret to be used when initialising the states.
genSharedSecret :: MonadRandom m => m SharedSecretKey
genSharedSecret = SharedSecretKey <$> getRandomBytes keyLen

-- | Returns a new Diffie-Hellman key pair.
generateDH :: MonadRandom m => m DHKeyPair
generateDH = do
  sk <- C25519.generateSecretKey
  let pk = C25519.toPublic sk
  return $ DHKeyPair sk pk

sskToRk :: SharedSecretKey -> RootKey
sskToRk (SharedSecretKey k) = RootKey k
