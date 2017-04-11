{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
module Ratchet.Types where

import Protolude

import           Data.Serialize (Serialize)
import           Crypto.Error (CryptoError)
import qualified Data.ByteArray as B
import qualified Data.Text as T
import qualified Data.HashMap.Strict as Map
import qualified Crypto.PubKey.Curve25519 as C25519

keyLen :: Int
keyLen = 32

data RatchetError =
    InternalError CryptoError
  | HMACMismatch
  | UnpaddingFailure
  | SkipMessageKeys
  deriving (Show, Eq)

data MessageHeader = MessageHeader 
  { dh_ratchet_pub_key :: ByteString   -- ^ public key
  , pn_mh              :: Int          -- ^ previous chain length
  , msg_number         :: Int
  } deriving (Show, Generic, Serialize)

newtype SharedSecretKey =
  SharedSecretKey B.ScrubbedBytes -- 32 bytes

newtype RootKey =
  RootKey B.ScrubbedBytes deriving Show -- 32 bytes

newtype ChainKey =
  ChainKey B.ScrubbedBytes deriving Show -- 32 bytes

newtype MessageKey =
  MessageKey B.ScrubbedBytes deriving Show -- 32 bytes

newtype PlainText =
  PlainText ByteString deriving (Show, Eq)

newtype AEADCipherText =
  AEADCipherText ByteString deriving (Show, Generic, Serialize)

newtype CipherText =
  CipherText ByteString deriving Show

newtype AssocData =
  AssocData ByteString deriving (Show, Generic, Serialize)

data DHKeyPair = DHKeyPair 
  { privKey :: C25519.SecretKey -- ^ Curve25519 private key
  , pubKey  :: C25519.PublicKey -- ^ Curve25519 public key
  } deriving Show

type MsgNum = Int
data StateRatchet = StateRatchet {
    dh_s       :: DHKeyPair        -- ^ DH Ratchet key pair (the "sending" or "self" ratchet key)
  , dh_r       :: Maybe ByteString -- ^ DH Ratchet public key (the "received" or "remote" key) 
  , rk         :: RootKey
  , ck_s       :: ChainKey         -- ^ sending
  , ck_r       :: Maybe ChainKey   -- ^ receiving
  , n_s, n_r   :: Int              -- ^ message number
  , p_n        :: Int              -- ^ number of messages in previous sending chain
  , mk_skipped :: Map.HashMap (ByteString, MsgNum) MessageKey
  , max_skip   :: MaxSkipped       -- ^ max number of message keys that can be skipped in a single chain.
} deriving Show

type MaxSkipped = Int
emptyRatchet :: MaxSkipped -> StateRatchet
emptyRatchet ms = StateRatchet {
    dh_r = Nothing
  , ck_s = panic "emptyRatchet: ck_s not set"
  , ck_r = Nothing
  , n_s  = panic "emptyRatchet: n_s not set"
  , n_r  = panic "emptyRatchet: n_r not set"
  , p_n  = panic "emptyRatchet: p_n not set"
  , mk_skipped = panic "emptyRatchet: mk_skipped not set"
  , dh_s = panic "emptyRatchet: dh_s not set"
  , rk   = panic "emptyRatchet: rk not set"
  , max_skip = if ms >= 0 then ms else 0
  }
