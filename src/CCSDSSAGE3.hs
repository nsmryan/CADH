module CCSDSSage3 () where

ethernetHeaderLengthBytes :: Int
ethernetHeaderLengthBytes = 14

ssmcDataSectionLength :: Int
ssmcDataSectionLength = 992

ethernetHeader = EthernetHeader $ BS.pack [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x05, 0x0a, 0x02, 0x04, 0x00]


{- TimeBroadcast -}
data TimeBroadcast =
  TimeBroadcast
  { timeBroadcastPreamble       :: Word8
  , timeBroadcastYear           :: Word16
  , timeBroadcastMonth          :: Word8
  , timeBroadcastDay            :: Word8
  , timeBroadcastHour           :: Word8
  , timeBroadcastMinute         :: Word8
  , timeBroadcastSecond         :: Word8
  , timeBroadcastSubseconds     :: Word32
  , timeBroadcastUTCConversion  :: Word16
  , timeBroadcastNonCCSDSSecond :: Word16 
  }

instance Binary TimeBroadcast where
  get = TimeBroadcast <$> get <*> get <*> get <*> get <*> get <*> get <*> get <*> get <*> get <*> get

  put (TimeBroadcast pream year mon day hour min sec subsec utcconv nonccsds) =
    put pream >> put year >> put mon >> put day >> put hour >> put min >> put sec >> put subsec >> put utcconv >> put nonccsds


{- Ethernet Header -}
--data EthernetHeader = EthernetHeader 
--  { ethernetHeaderPreample    :: ByteString
--  , ethernetHeaderDelimiter   :: Word8
--  , ethernetHeaderDestination :: ByteString
--  , ethernetHeaderSource      :: ByteString
--  , ethernetHeaderLength      :: Word16
--  } deriving (Show)
newtype EthernetHeader = EthernetHeader { unEthernetHeader :: ByteString } deriving (Show, Eq)

instance Binary EthernetHeader where
  --get = EthernetHeader <$> BGet.getByteString 7 <*> get <*> BGet.getByteString 6 <*> BGet.getByteString 6 <*> BGet.getWord16be
  --put (EthernetHeader pream del dest src len) = put pream >> put del >> put dest >> put src >> put len
  get = EthernetHeader <$> BGet.getByteString 14
  put (EthernetHeader header) = put header

{- SSMC Ethernet Packet -}
data SSMCEthernetPacket = SSMCEthernetPacket 
  { ssmcEthernetHeader  :: EthernetHeader
  , ssmcEthernetPayload :: SSMCPacket 
  --, ssmcEthernetCRC     :: Word32
  } deriving (Show)

instance Binary SSMCEthernetPacket where
  get = SSMCEthernetPacket <$> get <*> get -- <*> get
  put (SSMCEthernetPacket header payload {- crc -}) = put header >> put payload -- >> put crc

{- SSMC Reserved Area -}
data SSMCReserved = SSMCReserved 
  { virtualAddress      :: Word32
  , offsetToFirstPacket :: Word16
  , offsetToLastPacket  :: Word16
  , compareErrorsA      :: Word16
  , compareErrorsB      :: Word16
  , compareErrorsC      :: Word16
  , reserved            :: Word16
  } deriving (Show)

instance Binary SSMCReserved where
  get = SSMCReserved <$> get <*> get <*> get <*> get <*> get <*> get <*> get
  put (SSMCReserved virt firstOffset lastOffset compErrA compErrB compErrC reserved) = put virt >> put firstOffset >> put lastOffset >> put compErrA >> put compErrB >> put compErrC >> put reserved

{- SSMC Packet -}
--TODO tag with field names. tag payload with size and use singletons to get size when parsing.
newtype SSMCPacket = SSMCPacket { unSSMCPacket :: Rec Identity '[CCSDSPrimary, CCSDSSecondary, SSMCReserved, ByteString] } deriving (Show)

instance Binary SSMCPacket where
  get = do
    (pri, sec, reserved, payload) <- (,,,) <$> get <*> get <*> get <*> BGet.getByteString ssmcDataSectionLength
    return $ SSMCPacket (Identity pri :& Identity sec :& Identity reserved :& Identity payload :& RNil)

  put (SSMCPacket (Identity pri :& Identity sec :& Identity reserved :& Identity payload :& RNil)) = put pri >> put sec >> put reserved >> put payload


reportCount n = reportCount' 0 n 0
reportCount' !currentCount !maxCount !totalCount = 
  if currentCount == maxCount
    then yield totalCount >> reportCount' 0 maxCount totalCount
    else do
      a <- await
      reportCount' (succ currentCount) maxCount (succ totalCount)

removeEthernetHeader :: (MonadIO m, Monad m) => Pipe SSMCEthernetPacket SSMCPacket m r
removeEthernetHeader = do -- PP.tee (PP.map (Pre.show . unSSMCPacket . ssmcEthernetPayload) >-> PP.mapM (liftIO . Pre.putStrLn) >-> PP.drain) >-> 
  ssmcPacket <- await
  let ethHeader = ssmcEthernetHeader ssmcPacket 
  if ethHeader == ethernetHeader
    then yield $ ssmcEthernetPayload ssmcPacket
    else error $ "Ethernet header does not match: " ++ simpleHex (unEthernetHeader ethHeader)
  removeEthernetHeader 

processSSMCPackets :: Monad m => Pipe SSMCPacket (SSMCReserved, ByteString) m r
processSSMCPackets = PP.map ((getIdentity . rget (Proxy.Proxy :: Proxy.Proxy SSMCReserved) . unSSMCPacket) &&&
                             (getIdentity . rget (Proxy.Proxy :: Proxy.Proxy ByteString)   . unSSMCPacket))

-- TODO verify incrementing virtual addresses. if addresses don't increment, remove last packet, emit message, and restart at next full packet.

data PacketStreamState = HasMore | NeedsMore

packetByteStream :: (Monad m, MonadIO m) => Pipe (SSMCReserved, ByteString) ByteString m r
packetByteStream = do
  (ssmcReserved, bytes) <- await 
  let offsetToFirst = fromEnum $ offsetToFirstPacket ssmcReserved
  let offsetToLast = fromEnum $ offsetToLastPacket ssmcReserved
  packetByteStream' (offsetToLast - offsetToFirst) (BS.drop offsetToFirst bytes)

packetByteStream' last bytes =
  --liftIO $ Pre.putStrLn $ (Pre.show last) ++ "\n"
  case compare last (BS.length bytes) of
    -- Greater Than: need more data before yielding
    GT -> do
      (ssmcReserved, nextBytes) <- await
      let offsetToLast = fromEnum $ offsetToLastPacket ssmcReserved
      packetByteStream' (last + offsetToLast) (BS.append bytes nextBytes)

    -- Equal: yield what we have and continue
    EQ -> do
      yield bytes
      (ssmcReserved, nextBytes) <- await
      packetByteStream' (fromEnum $ offsetToLastPacket ssmcReserved) nextBytes

    -- Less Than: yield what we have and recurse
    LT -> do
      yield $ BS.take last bytes
      (ssmcReserved, nextBytes) <- await
      let offsetToLast = fromEnum $ offsetToLastPacket ssmcReserved
      let remaining = BS.drop last bytes
      packetByteStream' (BS.length remaining + offsetToLast) (BS.append remaining nextBytes)


retrieveLength :: Monad m => Pipe (ByteOffset, (EthernetHeader, SSMCPacket)) ByteOffset m r
retrieveLength = PP.map fst

getSeqCount :: SSMCPacket -> Word16
getSeqCount (SSMCPacket (Identity pri :& rest)) = ccsdsSeqCount pri

getApid :: SSMCPacket -> Word16
getApid (SSMCPacket (Identity pri :& rest)) = ccsdsApid pri

ssmcDataStream :: (Monad m, MonadIO m) => Handle -> Producer BS.ByteString m ()
ssmcDataStream hIn = void $ view decoded (PByte.fromHandle hIn) >-> removeEthernetHeader >-> processSSMCPackets >-> packetByteStream

packetProducer :: (Monad m) => Producer BS.ByteString m () -> Producer CCSDSPacket m ()
packetProducer prod = void $ view decoded prod

-- Need to create another producer which parses the inner bytestring stream.
mainStream :: IO ()
mainStream = do
  [fileName] <- getArgs
  withFile fileName ReadMode $ \ hIn ->
    runEffect $ packetProducer (ssmcDataStream hIn) >-> PP.map Pre.show >-> PP.map (++"|") >-> PP.mapM Pre.putStrLn >-> PP.drain
    -- runEffect $ packetProducer (ssmcDataStream hIn) >-> {- PP.map getSeqCount >-> reportCount 5000 >-> -} PP.show >-> PP.stdoutLn
