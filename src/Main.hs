module Main where

import Prelude as Pre

import Pipes.ByteString as PB
import Pipes.Binary
import Pipes as P
import Pipes.Prelude as PP
import Pipes.Parse as Parse

import Data.ByteString as B
import Data.ByteString.Lazy as BL
import Data.ByteString.Builder as BB
import qualified Data.Map as M
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import Data.Proxy
import Data.Either
import Data.Monoid
import Data.Foldable as F
import Data.Maybe
import Data.Set as S

import Control.Monad as M
import Control.Monad.Identity
import Control.Applicative

import System.IO

import CADH.DataDefs


type FileName = String

-- type HasHeader = Bool

-- many packets, same header with length
-- fixed length for all structures
-- length based on packet type field
-- length not known until decoding finished
data DataFormat
  = BinaryFormat
  -- HexFormat
  -- CSVFormat HasHeader
  -- TableConfig
  -- LinesConfig

data PacketSet
  = PacketSetSingle Name
  | PacketSetMany Name (M.Map Int Name) Container
     
data Channel
  = Channel DataFormat ChannelType
  | EmptyChannel

data ChannelType
  = FileChannel FileName
  -- TCPChannel DataFormat Port IPAddress
  -- UDPChannel DataFormat Port IPAddress
  -- SerialChannel

data PacketDef
  = PacketDef { packetName :: Name
              , packetDef :: Container
              }


ccsdsPacketIdentifier :: PacketSet
ccsdsPacketIdentifier = PacketSetSingle "CCSDSPacket"

ccsdsPacketDef :: PacketDef
ccsdsPacketDef = PacketDef "CCSDSPacket" ccsdsPacketContainer

ccsdsPacketContainer :: Container
ccsdsPacketContainer = Section "CCSDSPacket"
                               [ priHeader LittleEndian
                               , ccsdsDataSection
                               , ccsdsChecksum
                               ]

ccsdsDataSection :: Container
ccsdsDataSection =
  TlmPoint "CCSDSDataBuffer" (TlmBuff (VariableSize "CCSDSLength" (-1)) TlmAny)

priHeader :: Endianness -> Container
priHeader endianness =
  Section "PriHeader" [ firstWord endianness
                      , seqWord endianness
                      , ccsdsLength endianness
                      ]

ccsdsLength endianness = uint16Tlm endianness "CCSDSLength"

firstWord :: Endianness -> Container
firstWord endianness =
  let withinType = Uint16 endianness TlmAny
   in bitField "PriHeaderFirstWord"
               withinType
               [ TlmPoint "APID"          (TlmBits withinType 0 11 (Uint16 endianness TlmAny))
               , TlmPoint "SecHeaderFlag" (TlmBits withinType 11 1 (Uint8 TlmAny))
               , TlmPoint "PacketType"    (TlmBits withinType 12 1 (Uint8 TlmAny))
               , TlmPoint "CCSDSVersion"  (TlmBits withinType 13 3 (Uint8 TlmAny))
               ]

seqWord :: Endianness -> Container
seqWord endianness = 
  let withinType = Uint16 endianness TlmAny in 
    bitField "Seq"
             withinType
             [ TlmPoint "SeqFlag"  (TlmBits withinType 14  2 (Uint8 TlmAny))
             , TlmPoint "SeqCount" (TlmBits withinType  0 14 (Uint16 endianness TlmAny))
             ]
 
secHeader endianness = TlmPoint "SecHeader" (TlmArray (FixedSize 10) (Uint8 Proxy) [])
ccsdsHeader endianness = Section "CCSDSHeader" [priHeader endianness, secHeader endianness]

dataBuffer =
  container "SystemState" [arrTlm "Data" 108 (Uint8 Proxy)]

ccsdsChecksum = TlmPoint "CCSDSChecksum" (TlmPrim (Uint16 LittleEndian TlmAny))

systemStatePacket = PacketDef "SystemPacket" sys

sys = Section "Sys" [ ccsdsHeader LittleEndian
                    , uint8Tlm "stayInCheckResult"
                    , uint8Tlm "stayOutCheckResult"
                    , uint8Tlm "altitudeCheckResult"
                    , uint8Tlm "pad"
                    , uint32Tlmle "StateFlags"
                    , doubleTlmle "latitude"
                    , doubleTlmle "longitude"
                    , doubleTlmle "xPrimary"
                    , doubleTlmle "yPrimary"
                    , doubleTlmle "altitude"
                    , doubleTlmle "latitudeSecondary"
                    , doubleTlmle "longitudeSecondary"
                    , doubleTlmle "xSecondary"
                    , doubleTlmle "ySecondary"
                    , doubleTlmle "altitudeSecondary"
                    , doubleTlmle "altitudeOffset"
                    , doubleTlmle "velocityX"
                    , doubleTlmle "velocityY"
                    , doubleTlmle "velocityZ"
                    , doubleTlmle "minimumSafeDistance"
                    , doubleTlmle "minimumSafeDistanceAltitude"
                    , doubleTlmle "impactDistancePredicted"
                    , doubleTlmle "maxHeightPredicted"
                    , floatTlmle "distToStayIn"
                    , floatTlmle "distToStayOut"
                    , floatTlmle "differenceFromAltLimit"
                    , doubleTlmle "positionError"
                    , doubleTlmle "positionErrorAlt"
                    , floatTlmle "startTime"
                    , floatTlmle "endTime"
                    , ccsdsChecksum]


recommutate :: Container -> TlmDecoded -> Put
recommutate container tlmDecoded =
  case container of
    TlmPoint name basicTy -> 
      case M.lookup name tlmDecoded of
        Nothing ->
          error $ "Could not find " ++ name ++ " during encoding"

        Just tlmData ->
          recommutateTlmPoint $ tlmPayload tlmData

    Section name children -> 
      F.fold $ Pre.map (flip recommutate tlmDecoded) children 

    AllOf name children -> 
      -- FIXME if this failures, it would be better to try the next child
      recommutate (Pre.head children) tlmDecoded 

    OneOf name key choice -> 
      case M.lookup key tlmDecoded of
        Nothing -> error $ key ++ " not found in packet"

        Just tlm ->
          case tlmPayload tlm of
            TlmPrim prim ->
              case M.lookup (unwrapPrim prim) choice of
                Nothing ->
                  error $ "Could not find " ++ Pre.show tlm ++ " for key " ++ key

                Just tlmData ->
                  recommutate tlmData tlmDecoded

recommutateTlmPoint :: BasicData -> Put
recommutateTlmPoint tlmData = 
  case tlmData of
    TlmPrim prim ->
      recommutatePrim prim

    TlmChar (Identity chr) ->
      putCharUtf8 chr

    TlmDbl e (Identity dbl) ->
      case e of
        BigEndian -> 
          putDoublebe dbl
        LittleEndian -> 
          putDoublele dbl

    TlmFlt e (Identity flt) ->
      case e of
        BigEndian -> 
          putFloatbe flt
        LittleEndian -> 
          putFloatle flt

    TlmArray siz prim prims ->
      undefined

    TlmBuff siz bytes ->
      putByteString $ runIdentity bytes

    TlmBits primTy offset numBits prim ->
      -- NOTE bits are not layed down as they must be preceded by a field containing
      -- the full primitive telemtry point. This first field will be layed down by
      -- the recomming of AnyOf
      return ()

recommutatePrim prim = 
  case prim of
    Uint8 (Identity n) ->
      putWord8 n

    Uint16 e (Identity n) ->
      case e of
        BigEndian ->
          putWord16be n
        LittleEndian ->
          putWord16le n

    Uint32 e (Identity n) ->
      case e of
        BigEndian ->
          putWord32be n
        LittleEndian ->
          putWord32le n

    Uint64 e (Identity n) ->
      case e of
        BigEndian ->
          putWord64be n
        LittleEndian ->
          putWord64le n

    Sint8 (Identity n) ->
      putInt8 n

    Sint16 e (Identity n) ->
      case e of
        BigEndian ->
          putInt16be n
        LittleEndian ->
          putInt16le n

    Sint32 e (Identity n) ->
      case e of
        BigEndian ->
          putInt32be n
        LittleEndian ->
          putInt32le n

    Sint64 e (Identity n) ->
      case e of
        BigEndian ->
          putInt64be n
        LittleEndian ->
          putInt64le n

decommutate :: Container -> Get TlmDecoded
decommutate tlmDef = fst <$> decommutate' tlmDef M.empty 0

decommutate' :: Container -> TlmDecoded -> Int -> Get (TlmDecoded, Int)
decommutate' tlmDef tlmDecoded offset =
  case tlmDef of
    TlmPoint name ty ->
      do tlmData <- getBasic tlmDecoded ty
         let offset' = sizeOfBasic ty tlmDecoded
         return $ (M.insert name (Tlm name offset tlmData) tlmDecoded, offset + offset')

    Section name children ->
      let decom (tlmDecoded', offset') tlmDef' = decommutate' tlmDef' tlmDecoded' offset'
      in M.foldM decom (tlmDecoded, offset) children

    AllOf name children ->
      let decom (tlmDecoded', offsets) tlmDef' = 
            do (tlmDecoded'', offset') <- lookAhead $ decommutate' tlmDef' tlmDecoded' offset
               return (tlmDecoded'', offset' : offsets)
       in do (tlmDecoded', offsets) <- M.foldM decom (tlmDecoded, []) children
             let offset' = Pre.maximum offsets
             Data.Binary.Get.skip $ offset' - offset
             return (tlmDecoded', offset')

    OneOf name key map ->
      case M.lookup key tlmDecoded of
        Nothing -> error $ "key not found in telemetry packet"
        Just (Tlm _ _ (TlmPrim prim)) ->
          case M.lookup (unwrapPrim prim) map of
            Nothing ->
              error $ "Value of " ++ key ++ ", " ++ Pre.show prim ++ ", not found"
            Just tlmDef' ->
              decommutate' tlmDef' tlmDecoded offset

getPrim :: Prim f -> Get PrimData
getPrim ty = 
  case ty of
    Uint8 _ ->
      (Uint8 . Identity) <$> getWord8

    Uint16 e _ ->
      (Uint16 e . Identity) <$>
        (case e of
           BigEndian    -> getWord16be
           LittleEndian -> getWord16le)

    Uint32 e _ ->
      (Uint32 e . Identity) <$>
         (case e of
            BigEndian    -> getWord32be
            LittleEndian -> getWord32le)

    Uint64 e _ ->
      (Uint64 e . Identity)  <$>
         (case e of
            BigEndian    -> getWord64be
            LittleEndian -> getWord64le)

    Sint8 _ ->
      (Sint8 . Identity) <$> getInt8

    Sint16 e _ ->
      (Sint16 e . Identity) <$>
         (case e of
            BigEndian    -> getInt16be
            LittleEndian -> getInt16le)

    Sint32  e _ ->
      (Sint32 e . Identity) <$>
         (case e of
            BigEndian    -> getInt32be
            LittleEndian -> getInt32le)

    Sint64 e _ ->
      (Sint64 e . Identity) <$>
         (case e of
            BigEndian    -> getInt64be
            LittleEndian -> getInt64le)

getBasic :: TlmDecoded -> BasicTy -> Get BasicData
getBasic tlmDecoded ty = 
  case ty of
    TlmChar _ ->
      (TlmChar . Identity . toEnum . fromEnum) <$> getWord8

    TlmBits tyWithin offset numBits ty ->
      (TlmPrim . extractBits offset numBits ty) <$>
                    (getPrim tyWithin)

    TlmDbl e _ ->
      (TlmDbl e . Identity) <$>
         (case e of
            BigEndian    -> getDoublebe
            LittleEndian -> getDoublele)

    TlmFlt e _ ->
      (TlmFlt e . Identity) <$>
         (case e of
            BigEndian    -> getFloatbe
            LittleEndian -> getFloatle)

    TlmArray (FixedSize siz) ty _ ->
      (TlmArray (FixedSize siz) ty) <$>
         (Pre.sequence . Pre.replicate siz $ (getPrim ty))

    TlmBuff (FixedSize siz) _ ->
      (TlmBuff (FixedSize siz) . Identity) <$> getByteString siz

    TlmBuff (VariableSize name siz) val ->
      case tlmPayload <$> M.lookup name tlmDecoded of
        Nothing ->
          error $ name ++ " was not found as a length field. Map = " ++ Pre.show tlmDecoded

        Just (TlmPrim prim) -> 
          getBasic tlmDecoded (TlmBuff (FixedSize (unwrapPrim prim + siz)) val)

    TlmPrim prim ->
      TlmPrim <$> getPrim prim

    otherwise -> error $ "not implemented- getBasic for " ++ Pre.show ty

-- unwrap primitive data, shift to get bit offset, mask out higher bits, and wrap in primitive again
extractBits offset numBits ty prim =
  wrapPrim ty . mask numBits . (flip shiftR offset) . unwrapPrim $ prim

mask numBits bits = ((setBit zeroBits numBits) - 1) .&. bits

testSource = Channel BinaryFormat
                     (FileChannel "Logged_Data_20161216_1705_00_Fourth_Attempt_Full_Grid")

testSink = Channel BinaryFormat (FileChannel "outFile.bin")

sourceChannel channel =
  case channel of
    (Channel BinaryFormat (FileChannel fileName)) ->
      PB.fromHandle <$> openBinaryFile fileName ReadMode 

    EmptyChannel ->
      return . forever . yield $ B.empty

sinkChannel :: Channel -> IO (Consumer B.ByteString IO r)
sinkChannel channel =
  case channel of
    Channel BinaryFormat (FileChannel fileName) ->
      PB.toHandle <$> openBinaryFile fileName WriteMode 

    EmptyChannel ->
      return drain

{-
   FIXME add commands-
     decom [binary|csv|hex] [split|combine]
 -}
main = do
  source <- sourceChannel testSource
  sink   <- sinkChannel testSink
  runEffect $ (process source ccsdsPacketIdentifier [ccsdsPacketDef]) >->
              -- retrieveTlm "APID" >->
              -- printer >->
              PP.map (toStrict . runPut . recommutate ccsdsPacketContainer) >->
              sink

printSize :: Pipe PB.ByteString PB.ByteString IO r
printSize = PP.mapM (\a -> liftIO (Pre.print (B.length a)) >> return a)

process :: Producer PB.ByteString IO r ->
           PacketSet ->
           [PacketDef] ->
           Producer TlmDecoded IO (DecodingError, Producer PB.ByteString IO r)
process prod (PacketSetSingle pktName) [PacketDef nam container] =
  if pktName /= nam
     then error $ "packet name " ++ pktName ++ " does not equal " ++ nam
     else parsed (decodeGet . decommutate $ container) prod

process _ _ _ = error "PacketSetMany not implemented"

retrieveTlm :: Name -> Pipe TlmDecoded TlmData IO r
retrieveTlm tlmName = 
  PP.map $ M.findWithDefault (error $ tlmName ++ " count not found") tlmName

printer :: (Monad m, MonadIO m, Show a) => Pipe a a m r
printer = forever $ do
  a <- await
  liftIO $ Pre.print a
  yield a

