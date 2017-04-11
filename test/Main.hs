module Main where

import Protolude hiding ((<>))
import Data.Monoid ((<>))

import           Test.Tasty
import           Test.QuickCheck.Instances
import           Test.QuickCheck.Monadic
import qualified Test.Tasty.QuickCheck as QC


import           Data.ByteArray
import           Data.ByteString hiding (reverse, sort, filter)
import           Crypto.Random (getRandomBytes)
import           Data.Maybe (fromJust)
import qualified Data.ByteString as B

import Ratchet

newtype BS32 = BS32 ByteString deriving Show
instance QC.Arbitrary BS32 where
  arbitrary = BS32 <$> arbitraryBS 32

-- stolen from cryptonite
arbitraryBS :: Int -> QC.Gen ByteString
arbitraryBS n = B.pack `fmap` replicateM n QC.arbitrary

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [properties]

properties :: TestTree
properties = testGroup "Properties" [qcProps]

qcProps :: TestTree
qcProps = testGroup "(checked by QuickCheck)"
  [ QC.testProperty "ratchet test: simple" $
      (\plain1 plain2 ad -> monadicIO $ do
        b <- run $ doubleRatchetTest (plain1 :: ByteString)
                                     (plain2 :: ByteString)
                                     (ad :: ByteString)
        assert b)
  , QC.testProperty "ratchet test: ping pong" $
      (\plain1 plain2 ad -> monadicIO $ do
        b <- run $ doubleRatchetPingPongTest (plain1 :: ByteString)
                                             (plain2 :: ByteString)
                                             (ad :: ByteString)
        assert b)
  , QC.testProperty "ratchet test: msgs not ordered" $
      monadicIO $ do
        b <- run doubleRatchetNoOrderTest
        assert b
  ]

data CombinedState = CombinedState {
  alice, bob :: StateRatchet
}

doubleRatchetTest :: ByteString -> ByteString -> ByteString -> IO Bool
doubleRatchetTest plain1 plain2 ad = do
  let plain1' = PlainText $ convert plain1
      plain2' = PlainText $ convert plain2
      ad'     = AssocData $ convert ad

  cs <- initStates

  (val, cs')   <- sendReceiveAliceBob plain1' ad' cs
  (val', cs'') <- sendReceiveBobAlice plain2' ad' cs'

  return $ val && val'

doubleRatchetPingPongTest :: ByteString -> ByteString -> ByteString -> IO Bool
doubleRatchetPingPongTest plain1 plain2 ad = do
  let plain1' = PlainText $ convert plain1
      plain2' = PlainText $ convert plain2
      ad'     = AssocData $ convert ad
      nRounds = 10
      loop ctr cs acc
        | ctr >= nRounds = return acc
        | otherwise = do
          (val, cs')   <- sendReceiveAliceBob plain1' ad' cs
          (val', cs'') <- sendReceiveBobAlice plain2' ad' cs'

          loop (ctr + 1) cs'' $ val : val' : acc

  cs <- initStates
  and <$> loop 0 cs []

doubleRatchetNoOrderTest :: IO Bool
doubleRatchetNoOrderTest = do
  let nMsgs = 10
      idx   = 123
      createMessages :: Int -> 
                        [((MessageHeader, Either RatchetError AEADCipherText), PlainText, AssocData)] ->
                        StateT StateRatchet IO [(MessageHeader, AEADCipherText, PlainText, AssocData)]
      createMessages ctr acc
        | ctr >= nMsgs = do
            let msgs'  = filter (\((_, msg), _, _) -> isRight msg) acc
                msgs'' = fmap (\((mh, Right msg), p, ad) -> (mh, msg, p, ad)) msgs'
            return msgs''

        | otherwise = do
          plain <- lift $ PlainText <$> getRandomBytes 1337
          ad    <- lift $ AssocData <$> getRandomBytes 42
          msg   <- createMessage plain ad

          createMessages (ctr + 1) $ (msg, plain, ad) : acc

      receiveMessages [] acc = return acc
      receiveMessages ((mh, cipher, p, ad):ms) acc = do
          msg <- receiveMessage mh cipher ad
          let val = msg == Right p

          receiveMessages ms $ val : acc

  cs <- initStates
  let stateAlice = alice cs
      stateBob   = bob cs
  (msgs, _) <- runState' stateAlice $ createMessages 0 []

  let msgs' = fromJust . (flip atMay) idx $ permutations msgs
  
  (vals, _) <- runState' stateBob $ receiveMessages msgs' []
 
  return $ and vals

initStates :: IO CombinedState
initStates = do
  let maxSkipMsgs = 64
      stateAlice = emptyRatchet maxSkipMsgs
      stateBob   = emptyRatchet maxSkipMsgs
  sharedSecret <- genSharedSecret
  bobKP <- generateDH

  (_, stateAlice') <- runState' stateAlice $
                        ratchetInitAlice sharedSecret (pubKey bobKP)
  (_, stateBob') <- runState' stateBob $
                      ratchetInitBob sharedSecret bobKP

  return $ CombinedState stateAlice' stateBob'

sendReceiveAliceBob :: PlainText -> AssocData -> CombinedState -> IO (Bool, CombinedState)
sendReceiveAliceBob = sendReceive

sendReceiveBobAlice :: PlainText -> AssocData -> CombinedState -> IO (Bool, CombinedState)
sendReceiveBobAlice plainT ad cs = do
  let cs' = swapStates cs
  (val, cs'') <- sendReceive plainT ad cs'
  let cs''' = swapStates cs''
  return (val, cs''')

sendReceive :: PlainText
                -> AssocData
                -> CombinedState
                -> IO (Bool, CombinedState)
sendReceive plainT@(PlainText pt) ad cs = do
  let (CombinedState stateSender stateReceiver) = cs
  ((mh, cipher), stateSender') <- runState' stateSender $
                                    ratchetEncrypt plainT ad

  case cipher of
    Left err -> do
      print err
      let cs' = CombinedState stateSender' stateReceiver
      return (False, cs')

    Right cipherText -> do
      (plain, stateReceiver') <- runState' stateReceiver $ do
        ratchetDecrypt mh cipherText ad
      let cs' = CombinedState stateSender' stateReceiver'
      case plain of
        Left err -> do
          print err
          return (False, cs')

        Right (PlainText plainText) ->
          return (plainText `constEq` pt, cs')

receiveMessage :: MessageHeader
                  -> AEADCipherText
                  -> AssocData
                  -> StateT StateRatchet IO (Either RatchetError PlainText)
receiveMessage = ratchetDecrypt

createMessage :: PlainText
                 -> AssocData
                 -> StateT
                      StateRatchet IO (MessageHeader, Either RatchetError AEADCipherText)
createMessage = ratchetEncrypt

swapStates :: CombinedState -> CombinedState
swapStates (CombinedState a b) = CombinedState b a

runState' :: s -> StateT s m a -> m (a, s)
runState' = flip runStateT
