import Prelude
import           System.Environment (getArgs)
import           Network.Socket hiding (recv)
import           Network.Socket.ByteString (recv, sendAll)
import           Control.Concurrent
import           Control.Concurrent.MVar
import           Data.Monoid ((<>))
import           Data.Serialize
import           Control.Monad.State
import           Control.Applicative (liftA)
import           Crypto.Error
import           Crypto.PubKey.Curve25519
import           Crypto.Random
import qualified Data.ByteArray          as BA
import qualified Data.ByteArray.Encoding as BAE
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Char8   as BSC

import Ratchet

data Input =
    Keyboard BS.ByteString
  | Wire BS.ByteString

port :: String
port = "12345"

host :: String
host = "localhost"

main :: IO ()
main = do
  let port = "12345"
      host = "localhost"
  arg <- getArgs
  
  case arg of
    ["server"] -> server
    ["client"] -> client
    _          -> usage

maxSkipMsgs :: MaxSkipped
maxSkipMsgs = 64

client :: IO ()
client = withSocketsDo $ do
  let stateBob   = emptyRatchet maxSkipMsgs
  (ssk, bobsKeyPair) <- readSharedData
  mvar <- newEmptyMVar
  addrinfos <- getAddrInfo Nothing (Just host) (Just port)
  let serveraddr = head addrinfos
  conn <- socket (addrFamily serveraddr) Stream defaultProtocol
  connect conn (addrAddress serveraddr)
  putStrLn "Connected to server."
  forkFinally (wireLoop conn mvar) (\_ -> close conn)
  forkIO $ inpLoop conn mvar
  evalState' stateBob $ do
    ratchetInitBob ssk bobsKeyPair
    handle conn mvar

server :: IO ()
server = withSocketsDo $ do
  let maxConnQueue = 1
      stateAlice = emptyRatchet maxSkipMsgs
  (ssk, bobsKeyPair) <- readSharedData

  mvar <- newEmptyMVar
  addrinfos <- getAddrInfo
               (Just $ defaultHints {addrFlags = [AI_PASSIVE]})
               Nothing
               (Just port)
  let serveraddr = head addrinfos
  sock <- socket (addrFamily serveraddr) Stream defaultProtocol
  setSocketOption sock ReuseAddr 1
  bind sock (addrAddress serveraddr)
  listen sock maxConnQueue

  putStrLn "Waiting for client to connect..."
  (conn, _) <- accept sock
  putStrLn "Client connected."
  forkFinally (wireLoop conn mvar) (\_ -> close conn)
  forkIO $ inpLoop conn mvar
  evalState' stateAlice $ do
    ratchetInitAlice ssk (pubKey bobsKeyPair)
    handle conn mvar

handle :: Socket -> MVar Input -> StateT StateRatchet IO ()
handle conn mvar = do
  inp <- lift $ takeMVar mvar

  case inp of
    Keyboard str -> do
        let adLen = 42
        ad <- lift $ AssocData <$> getRandomBytes adLen
        (mh, payload) <- ratchetEncrypt (PlainText $ BA.convert str) ad
        case payload of
          Left err ->
            lift $ print err
          
          Right cipher -> do
            let msg = encode (mh, cipher, ad)
            lift $ sendAll conn msg

    Wire msg -> do
      case decode msg of
        Left err ->
          lift $ putStrLn $ "Could not decode received data: " <> err

        Right (mh, cipher, ad) -> do
          dec <- ratchetDecrypt mh cipher ad
          case dec of
            Left err ->
              lift $ print err

            Right (PlainText plain) -> do
              let pre = "\nMessage received: "
              lift $ putStrLn $ pre <> show plain

  handle conn mvar

inpLoop :: Socket -> MVar Input -> IO ()
inpLoop conn mvar = do
  putStr "Type a message: "
  str <- getLine
  putMVar mvar $ Keyboard $ BSC.pack str

  inpLoop conn mvar

wireLoop :: Socket -> MVar Input -> IO ()
wireLoop conn mvar = do
  bs <- recv conn 1024
  putMVar mvar $ Wire bs

  wireLoop conn mvar

usage :: IO ()
usage = putStrLn "stack repl Example.hs \"server\" | \"client\""

-- helper functions
evalState' :: Monad m => s -> StateT s m a -> m a
evalState' = flip evalStateT

readSharedData :: IO (SharedSecretKey, DHKeyPair)
readSharedData = do
  let extract pub priv = do
      priv' <- secretKey priv
      pub'  <- publicKey pub
      return (priv', pub')
  let convert = BAE.convertFromBase BAE.Base64

  Right bytes <- liftA convert $ BS.readFile "ssk"
  let ssk = SharedSecretKey bytes

  Right pub  <- liftA convert $ BS.readFile "bob_public"
  Right priv <- liftA convert $ BS.readFile "bob_private"

  let keys = extract pub priv
  case keys of
    CryptoFailed err ->
      undefined

    CryptoPassed (priv', pub') ->
      return (ssk, DHKeyPair priv' pub')
