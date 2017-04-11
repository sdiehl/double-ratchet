{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
module Ratchet.Defaults where

import Protolude hiding ((<>))
import Data.Monoid ((<>))

import qualified Crypto.PubKey.Curve25519 as C25519
import qualified Crypto.KDF.HKDF as HKDF
import qualified Data.ByteArray as B
import qualified Crypto.MAC.HMAC as HMAC
import qualified Data.Text as T
import           Data.Serialize
import           Crypto.Error
import           Crypto.Cipher.AES
import           Crypto.Random.Types
import           Crypto.Hash
import           Crypto.Cipher.Types
import           Crypto.Data.Padding (unpad, pad, Format(..))

import Ratchet.Types

-- | Returns the output from the Diffie-Hellman calculation between the private
-- key from the DH key pair dh_pair and the DH public key dh_pub. If the DH
-- function rejects invalid public keys, then this function may raise an
-- exception which terminates processing.
--
-- > DH(dh_pair, dh_pub): 
dh :: DHKeyPair -> ByteString -> C25519.DhSecret
dh pair pubk =
  case C25519.publicKey pubk of
    CryptoFailed err ->
      panic $ T.pack $ show err

    CryptoPassed pubk' ->
      C25519.dh pubk' $ privKey pair

-- This function is recommended to be implemented using HKDF [3] with SHA-256 or
-- SHA-512 [8], using rk as HKDF salt, dh_out as HKDF input key material, and an
-- application-specific byte sequence as HKDF info. The info value should be
-- chosen to be distinct from other uses of HKDF in the application.  Returns a
-- pair (32-byte root key, 32-byte chain key) as the output of applying a KDF
-- keyed by a 32-byte root key rk to a Diffie-Hellman output dh_out.
--
-- > KDF_RK(rk, dh_out): 
kdfRk :: RootKey -> C25519.DhSecret -> (RootKey, ChainKey)
kdfRk (RootKey rk) dhOut =
  let prk = HKDF.extract rk dhOut :: HKDF.PRK SHA512
      keys = HKDF.expand prk info keyLens
      (rk', ck) = B.splitAt keyLen keys
  in (RootKey rk', ChainKey ck)

  where
    keyLens = keyLen * 2
    info = "\xDE\xAD\xCO\xDE" :: B.ScrubbedBytes

-- | Returns a pair (32-byte chain key, 32-byte message key) as the output of
-- applying a KDF keyed by a 32-byte chain key ck to some constant.
-- 
-- HMAC [2] with SHA-256 or SHA-512 [8] is recommended, using ck as the HMAC key
-- and using separate constants as input (e.g. a single byte 0x01 as input to
-- produce the message key, and a single byte 0x02 as input to produce the next
-- chain key).
kdfCk :: ChainKey -> (ChainKey, MessageKey)
kdfCk (ChainKey ck) =
  let ck' = HMAC.hmac ck ckMsg :: HMAC.HMAC SHA512
      mk  = HMAC.hmac ck mkMsg :: HMAC.HMAC SHA512
  in (ChainKey $ B.convert ck', MessageKey $ B.convert mk)

  where
    ckMsg = "\x02" :: B.ScrubbedBytes
    mkMsg = "\x01" :: B.ScrubbedBytes

-- | Returns an AEAD encryption of plaintext with message key mk [5]. The
-- associated_data is authenticated but is not included in the ciphertext.
-- Because each message key is only used once, the AEAD nonce may handled in
-- several ways: fixed to a constant; derived from mk alongside an independent
-- AEAD encryption key; derived as an additional output from KDF_CK(); or chosen
-- randomly and transmitted.
encrypt :: MessageKey -> PlainText -> AssocData
          -> Either RatchetError AEADCipherText
encrypt mk plainText (AssocData assocData) = do
  let (encKey, authKey, iv) = genKeys mk
  (CipherText cipherText) <- encryptAES256 plainText encKey iv
  let authMsg = assocData <> cipherText
      hmacVal = HMAC.hmac authKey authMsg :: HMAC.HMAC SHA512
  return $ AEADCipherText $ cipherText <> (B.convert hmacVal)

  where
    encryptAES256 :: PlainText -> B.ScrubbedBytes
                      -> Maybe (IV AES256)
                      -> Either RatchetError CipherText
    encryptAES256 _ _ Nothing = Left $ InternalError CryptoError_IvSizeInvalid
    encryptAES256 (PlainText plain) encKey (Just iv) =
      case cipherInit encKey :: CryptoFailable AES256 of
        CryptoFailed err ->
          Left $ InternalError err

        CryptoPassed c -> do
          let padded = pad (PKCS7 $ blockSize c) plain
          return $ CipherText $ cbcEncrypt c iv padded

genKeys :: MessageKey
          -> (B.ScrubbedBytes, B.ScrubbedBytes, Maybe (IV AES256))
genKeys (MessageKey mk) =
  let prk = HKDF.extract hkdfSalt mk :: HKDF.PRK SHA512
      keys = HKDF.expand prk info outLength
      (encKey, authKey, iv) = extractKeys keys
      iv' = makeIV iv :: Maybe (IV AES256)
  in (encKey, authKey, iv')

  where
    hkdfSalt = B.replicate outLength (0 :: Word8) :: B.Bytes
    outLength = encKeyLen + authKeyLen + ivLen
    info = "\x01\x03\x03\x07" :: ByteString
    encKeyLen = keyLen -- 32
    authKeyLen = keyLen -- 32
    ivLen = 16

    extractKeys keys =
      let (encKey, rest) = B.splitAt encKeyLen keys
          (authKey, iv) = B.splitAt authKeyLen rest
      in (encKey, authKey, iv)

-- | Returns the AEAD decryption of ciphertext with message key mk. If
-- authentication fails, an exception will be raised that terminates processing.
decrypt :: MessageKey -> AEADCipherText -> AssocData
          -> Either RatchetError PlainText
decrypt mk (AEADCipherText aeadCipherText) (AssocData assocData) = do
  let cutOff = B.length aeadCipherText - hashDigestSize SHA512
      (cipherText, digest) = B.splitAt cutOff aeadCipherText
      (decKey, authKey, iv) = genKeys mk
  pt@(PlainText plainText) <- decryptAES256 (CipherText cipherText) decKey iv
  let authMsg = assocData <> cipherText
      hmacVal = B.convert (HMAC.hmac authKey authMsg :: HMAC.HMAC SHA512)
  if hmacVal /= digest
    then Left HMACMismatch
    else return pt

  where
    decryptAES256 :: CipherText -> B.ScrubbedBytes
                   -> Maybe (IV AES256)
                   -> Either RatchetError PlainText
    decryptAES256 _ _ Nothing =
        Left $ InternalError $ CryptoError_IvSizeInvalid
    decryptAES256 (CipherText cipherText) decKey (Just iv) =
      case cipherInit decKey :: CryptoFailable AES256 of
        CryptoFailed err ->
          Left $ InternalError err

        CryptoPassed c -> do
          let padded = cbcDecrypt c iv cipherText
          case unpad (PKCS7 $ blockSize c) padded of
            Nothing ->
              Left UnpaddingFailure

            Just plain ->
              return $ PlainText plain

-- | Creates a new message header containing the DH ratchet public key from the
-- key pair in dh_pair, the previous chain length pn, and the message number n.
-- The returned header object contains ratchet public key dh and integers pn and
-- n.
type PrevChainLen = Int
header :: DHKeyPair -> PrevChainLen -> MsgNum -> MessageHeader
header pair pn_ n =
  MessageHeader (B.convert $ pubKey pair) pn_ n

-- | t Encodes a message header into a parseable byte sequence, prepends the ad
-- byte sequence, and returns the result. If ad is not guaranteed to be a
-- parseable byte sequence, a length value should be prepended to the output to
-- ensure that the output is parseable as a unique pair (ad, header).
concat :: AssocData -> MessageHeader -> AssocData
concat (AssocData ad) h =
  AssocData $ ad <> (B.convert . encode) h
