{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
module CADH where

import Prelude as Pre

import Data.Binary as B
import Data.Binary.Get as BGet
import Data.Binary.Put as BPut
import Data.Binary.Bits as Bi
import Data.Binary.Bits.Get as BiGet
import Data.Binary.Bits.Put as BiPut
import Data.Word
import Data.Bits
import Data.Proxy as Proxy
import Data.Vinyl
import Data.Vinyl.Core
import Data.Vinyl.Lens
import Data.Vinyl.Functor
import Data.Either

import Data.Foldable

import Debug.Trace

import Pipes as P
import Pipes.Prelude as PP
import Pipes.ByteString as PByte
import Pipes.Binary as PBin

import Hexdump

import Lens.Family2

import Control.Arrow
import Control.Applicative

import System.IO
import System.Environment

import Utils


apidLengthBits :: Int
apidLengthBits = 11

seqFlagLengthBits :: Int
seqFlagLengthBits = 2

sequenceCountLengthBits :: Int
sequenceCountLengthBits = 14

versionLengthBits :: Int
versionLengthBits = 3

timeIDLengthBits :: Int
timeIDLengthBits = 2

packetTypeLengthBits :: Int
packetTypeLengthBits = 4


{- Primary Header -}
data CCSDSPrimary = 
  CCSDSPrimary 
  { ccsdsVersion       :: CCSDSVersion
  , ccsdsType          :: CCSDSType 
  , ccsdsSecHeaderFlag :: CCSDSSecondaryHeaderFlag
  , ccsdsApid          :: Word16 
  , ccsdsSeqFlag       :: CCSDSSequenceFlag
  , ccsdsSeqCount      :: Word16 
  , ccsdsPacketLen     :: Word16
  } deriving (Show)

instance Binary CCSDSPrimary where
  get = do
    (ver, typ, secFlag, apid) <- runBitGet $ (,,,) <$> getBitCCSDVersion
                                                   <*> getBitCCSDSType
                                                   <*> getBitSecondaryHeaderFlag
                                                   <*> BiGet.getWord16be apidLengthBits

    (seqFlag, seqCount) <- runBitGet $ (,) <$> getBitSequenceFlag
                                           <*> BiGet.getWord16be sequenceCountLengthBits

    packLen <- get
    let pri = CCSDSPrimary ver typ secFlag apid seqFlag seqCount packLen
    --return $ trace (Pre.show pri) pri
    return pri

  put (CCSDSPrimary ver typ secFlag apid seqFlag seq len) =
    do runBitPut (putBitCCSDVersion ver             >>
                  putBitCCSDSType typ               >>
                  putBitSecondaryHeaderFlag secFlag >>
                  BiPut.putWord16be apidLengthBits apid)
       runBitPut (putBitSequenceFlag seqFlag >> BiPut.putWord16be sequenceCountLengthBits seq)
       BPut.putWord16be len

ccsdsLength primaryHeader = ccsdsPacketLen primaryHeader + 7

{- Secondary Header -}
data CCSDSSecondary = 
  CCSDSSecondary 
  { ccsdsTimestamp          :: Word32
  , ccsdsVernier            :: Word8
  , ccsdsTimeID             :: CCSDSTimeID
  , ccsdsCheckwordIndicator :: CCSDSCheckwordIndicator
  , ccsdsZOETlm             :: CCSDSZoe
  , ccsdsPacketType         :: CCSDSPacketType 
  , ccsdsWord3              :: Word16
  , ccsdsWord4              :: Word16 
  } deriving (Show)

instance Binary CCSDSSecondary where
  get = do
    time <- get
    vern <- get
    (timeID, check, zoe, packTyp) <- runBitGet $ (,,,) <$> getBits 2 <*> getBits 1 <*> getBits 1 <*> getBits 4
    word3 <- BGet.getWord16be
    word4 <- BGet.getWord16be
    let sec = CCSDSSecondary time vern timeID check zoe packTyp word3 word4
    --return $ trace (Pre.show sec) sec
    return sec

  put (CCSDSSecondary tim vern timeID checkInd zoe packTyp word3 word4) =
    put tim >> put vern >> runBitPut (putBits 2 timeID >> putBits 1 checkInd >> putBits 1 zoe >> putBits 4 packTyp) >> BPut.putWord16be word3 >> BPut.putWord16be word4


{- CCSDSZoe -}
data CCSDSZoe = CCSDS_NOT_ZOE | CCSDS_ZOE deriving (Show, Eq, Enum)

instance BinaryBit CCSDSZoe where
  putBits = putBitsEnum 1
  getBits = getBitsEnum 1

getBitZoe :: BitGet CCSDSZoe 
getBitZoe = getBits 1
putBitZoe :: CCSDSZoe -> BitPut ()
putBitZoe = putBits 1

{- CCSDSType -}
data CCSDSType = CCSDS_COMMAND_TYPE | CCSDS_DATA_TYPE
                 deriving (Show, Eq, Enum)

instance BinaryBit CCSDSType where
  putBits = putBitsEnum 1
  getBits = getBitsEnum 1

getBitCCSDSType :: BitGet CCSDSType 
getBitCCSDSType = getBits 1
putBitCCSDSType :: CCSDSType -> BitPut ()
putBitCCSDSType = putBits 1

{- CCSDSSecondaryHeaderFlag -}
data CCSDSSecondaryHeaderFlag = CCSDS_SECONDARY_HEADER_NOT_PRESENT | CCSDS_SECONDARY_HEADER_PRESENT
                                deriving (Show, Eq, Enum)

instance BinaryBit CCSDSSecondaryHeaderFlag where
  putBits = putBitsEnum 1
  getBits = getBitsEnum 1

getBitSecondaryHeaderFlag :: BitGet CCSDSSecondaryHeaderFlag 
getBitSecondaryHeaderFlag = getBits 1
putBitSecondaryHeaderFlag :: CCSDSSecondaryHeaderFlag -> BitPut ()
putBitSecondaryHeaderFlag = putBits 1

{- CCSDSCheckwordIndicator -}
data CCSDSCheckwordIndicator = CCSDS_CHECKWORD_PRESENT | CCSDS_CHECKWORD_NOT_PRESENT
                               deriving (Show, Eq, Enum)

instance BinaryBit CCSDSCheckwordIndicator where
  putBits = putBitsEnum 1
  getBits = getBitsEnum 1

getBitCheckwordIndicator :: BitGet CCSDSCheckwordIndicator 
getBitCheckwordIndicator = getBits 1
putBitCheckwordIndicator :: CCSDSCheckwordIndicator -> BitPut ()
putBitCheckwordIndicator = putBits 1

{- CCSDSTimeID -}
data CCSDSTimeID = CCSDS_TIMEID_TIME_NOT_USED
                 | CCSDS_TIMEID_GEN
                 | CCSDS_TIMEID_TIME_TAGGED_CMD
                 | CCSDS_TIMEID_NOT_USED
                 deriving (Show, Eq, Enum)

instance BinaryBit CCSDSTimeID where
  putBits = putBitsEnum timeIDLengthBits
  getBits = getBitsEnum timeIDLengthBits

getBitTimeID :: BitGet CCSDSTimeID 
getBitTimeID = getBits timeIDLengthBits
putBitTimeID :: CCSDSTimeID -> BitPut ()
putBitTimeID = putBits timeIDLengthBits

{- CCSDSPacketType -}
data CCSDSPacketType = CCSDS_PKT_TYPE_DATA_DUMP
                     | CCSDS_PKT_TYPE_DATA_TLM
                     | CCSDS_PKT_TYPE_DATA_PPS
                     | CCSDS_PKT_TYPE_DATA_ANC
                     | CCSDS_PKT_TYPE_CMD_ESS
                     | CCSDS_PKT_TYPE_CMD_SYS
                     | CCSDS_PKT_TYPE_CMD_RTC
                     | CCSDS_PKT_TYPE_CMD_DLD
                     | CCSDS_PKT_TYPE_UNKNOWN Int
                     deriving (Show, Eq)

instance Enum CCSDSPacketType where
  fromEnum CCSDS_PKT_TYPE_DATA_DUMP = 1
  fromEnum CCSDS_PKT_TYPE_DATA_TLM  = 4
  fromEnum CCSDS_PKT_TYPE_DATA_PPS  = 6
  fromEnum CCSDS_PKT_TYPE_DATA_ANC  = 7
  fromEnum CCSDS_PKT_TYPE_CMD_ESS   = 8
  fromEnum CCSDS_PKT_TYPE_CMD_SYS   = 9
  fromEnum CCSDS_PKT_TYPE_CMD_RTC   = 10
  fromEnum CCSDS_PKT_TYPE_CMD_DLD   = 11
  fromEnum (CCSDS_PKT_TYPE_UNKNOWN n) = n

  toEnum 1  = CCSDS_PKT_TYPE_DATA_DUMP
  toEnum 4  = CCSDS_PKT_TYPE_DATA_TLM
  toEnum 6  = CCSDS_PKT_TYPE_DATA_PPS
  toEnum 7  = CCSDS_PKT_TYPE_DATA_ANC
  toEnum 8  = CCSDS_PKT_TYPE_CMD_ESS
  toEnum 9  = CCSDS_PKT_TYPE_CMD_SYS
  toEnum 10 = CCSDS_PKT_TYPE_CMD_RTC
  toEnum 11 = CCSDS_PKT_TYPE_CMD_DLD
  toEnum n = CCSDS_PKT_TYPE_UNKNOWN n

instance BinaryBit CCSDSPacketType where
  putBits = putBitsEnum packetTypeLengthBits
  getBits = getBitsEnum packetTypeLengthBits

getBitPacketType :: BitGet CCSDSPacketType
getBitPacketType = getBits packetTypeLengthBits
putBitPacketType :: CCSDSPacketType -> BitPut ()
putBitPacketType = putBits packetTypeLengthBits

{- CCSDSSequenceFlag -}
data CCSDSSequenceFlag = CCSDS_SEQ_FLAG_CONT
                       | CCSDS_SEQ_FLAG_FIRST
                       | CCSDS_SEQ_FLAG_LAST
                       | CCSDS_SEQ_FLAG_UNSEGMENTED
                       deriving (Show, Eq, Enum)

instance BinaryBit CCSDSSequenceFlag where
  putBits = putBitsEnum seqFlagLengthBits
  getBits = getBitsEnum seqFlagLengthBits

getBitSequenceFlag :: BitGet CCSDSSequenceFlag
getBitSequenceFlag = getBits seqFlagLengthBits
putBitSequenceFlag :: CCSDSSequenceFlag -> BitPut ()
putBitSequenceFlag = putBits seqFlagLengthBits

{- CCSDSVersion -}
data CCSDSVersionID = CCSDS_VERSION_ID_NOT_VALID | CCSDS_VERSION_ID_DEFAULT_VERSION
                    deriving (Show, Eq, Enum)

data CCSDSVersion = CCSDS_VERSION Word8
                    deriving (Show, Eq)

instance BinaryBit CCSDSVersion where
  putBits n (CCSDS_VERSION ver) = putBitsEnum versionLengthBits n ver
  getBits n = CCSDS_VERSION <$> getBitsEnum versionLengthBits n

getBitCCSDVersion :: BitGet CCSDSVersion 
getBitCCSDVersion = getBits versionLengthBits
putBitCCSDVersion :: CCSDSVersion -> BitPut ()
putBitCCSDVersion = putBits versionLengthBits

{- Generic CCSDS Packet (including ISS secondary header -}
newtype CCSDSPacket = CCSDSPacket { unCCSDSPacket :: Rec Identity '[CCSDSPrimary, CCSDSSecondary, ByteString, Maybe Checksum] }

instance Show CCSDSPacket where
  show (CCSDSPacket (Identity pri :& Identity sec :& Identity byteData :& Identity checksum :& RNil)) =
    Pre.concat [Pre.show pri, ",",  Pre.show sec, ",",  simpleHex byteData, ",",  Pre.show checksum]

type Checksum = Word16

instance Binary CCSDSPacket where
  get = do
      (pri, sec) <- (,) <$> get <*> get
      payload <- BGet.getByteString (fromEnum $ ccsdsLength pri)
      checksum <- case ccsdsCheckwordIndicator sec of
        CCSDS_CHECKWORD_PRESENT     -> Just <$> get
        CCSDS_CHECKWORD_NOT_PRESENT -> return Nothing
      return $ CCSDSPacket (Identity pri :& Identity sec :& Identity payload :& Identity checksum :& RNil)

  put (CCSDSPacket (Identity pri :& Identity sec :& Identity payload :& Identity checksum :& RNil)) = 
    do put pri >> put sec >> put payload
       forM_ checksum put

