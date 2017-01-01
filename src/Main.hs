module Main where

import Prelude as Pre

import Pipes.ByteString as PB
import Pipes as P
import Pipes.Prelude as PP

import Data.ByteString as B
import Data.ByteString.Lazy as BL
import Data.Map as M
import Data.Binary.Get
import Data.Bits

import Control.Monad as M
import Control.Applicative

import System.IO

import CADH.DataDefs



priHeader endianness =
  Section "PriHeader" [ firstWord endianness
                      , seqWord endianness
                      , uint16Tlm endianness "Length"
                      ]

firstWord endianness =
  let withinType = TyUint16 endianness in 
  AllOf "PriHeaderFirstWord" [ Buffer "APID"          (TyBits withinType 0 11 (TyUint16 endianness))
                             , Buffer "SecHeaderFlag" (TyBits withinType 11 1 TyUint8)
                             , Buffer "PacketType"    (TyBits withinType 12 1 TyUint8)
                             , Buffer "CCSDSVersion"  (TyBits withinType 13 3 TyUint8)
                             ]
seqWord endianness = 
  let withinType = TyUint16 endianness in 
  AllOf "Seq" [ Buffer "SeqFlag"  (TyBits withinType 14  2 TyUint8)
              , Buffer "SeqCount" (TyBits withinType  0 14 (TyUint16 endianness))
              ]
 
secHeader endianness = Buffer "SecHeader" (TyBuff 10 TyUint8)
ccsdsHeader endianness = Section "CCSDSHeader" [priHeader endianness, secHeader endianness]

dataBuffer =
  container "SystemState" [arrTlm "Data" 108 TyUint8]

checksum = Buffer "Checksum" (TyPrim (TyUint16 LittleEndian))

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
                    , checksum]

decode :: Container -> TlmDecoder
decode = fst . decode' 0 M.empty

decode' offset map tlmDef =
  case tlmDef of
    Buffer nam ty ->
      (M.insert nam (Tlm nam offset ty) map, offset + sizeOfBasic ty)

    AllOf nam children -> decodeAllOf nam children map offset offset

    -- OneOf nam key oneOfMap ->
    --   let dat = M.findWithDefault (error "lookup couldn't find " ++ Pre.show key) key map
    --   in case tlmPayload dat of
    --        Prim prim -> decode' offset map $ M.findWithDefault (error "lookup couldn't find " ++ Pre.show prim) (unwrapPrim prim) oneOfMap
    --        otherwise -> error $ "can't decode a OneOf with a non-primitive key (" ++ nam ++ ")"

    Section nam [] -> (map, offset)
    Section nam (a:as) ->
      let (map', offset') = decode' offset map a
      in decode' offset' map' (Section nam as)

decodeAllOf nam [] map offset offset' = (map, offset')
decodeAllOf nam (a:as) map offset offset' = 
  let (map', offset'') = decode' offset map a
  in decodeAllOf nam as map' offset (max offset' offset'')

decomDef :: Container -> PB.ByteString -> TlmDecoded
decomDef def bytes = decom (decode def) bytes

decom :: TlmDecoder -> PB.ByteString -> TlmDecoded
decom tlmDecoder bytes =
  let insertDecommed map tlm = M.insert (tlmName tlm) (decomTlm tlm bytes) map
  in M.foldl insertDecommed M.empty tlmDecoder

decomTlm :: TlmDef -> PB.ByteString -> TlmData
decomTlm (Tlm nam offset ty) bytes =
  let decomData = decomBasic ty $ B.drop offset bytes
  in Tlm nam offset decomData

decomBasic ty bytes = runGet (getBasic ty) $ BL.fromStrict bytes

getPrim ty = 
  case ty of
    TyUint8 ->
      Uint8 <$> getWord8

    TyUint16 endianness ->
      Uint16 <$> (case endianness of
                    BigEndian    -> getWord16be
                    LittleEndian -> getWord16le)

    TyUint32 endianness ->
      Uint32 <$> (case endianness of
                    BigEndian    -> getWord32be
                    LittleEndian -> getWord32le)

    TyUint64 endianness ->
      Uint64 <$> (case endianness of
                    BigEndian    -> getWord64be
                    LittleEndian -> getWord64le)

    TyInt8 ->
      Sint8 <$> (getInt8)

    TyInt16  endianness ->
      Sint16 <$> (case endianness of
                    BigEndian    -> getInt16be
                    LittleEndian -> getInt16le)

    TyInt32  endianness ->
      Sint32 <$> (case endianness of
                    BigEndian    -> getInt32be
                    LittleEndian -> getInt32le)

    TyInt64  endianness ->
      Sint64 <$> (case endianness of
                    BigEndian    -> getInt64be
                    LittleEndian -> getInt64le)

getBasic ty = 
  case ty of
    TyChar ->
      (Chr . toEnum . fromEnum) <$> getWord8

    TyBits tyWithin offset numBits ty ->
      (Prim . extractBits offset numBits ty) <$> getPrim tyWithin

    TyDbl  endianness ->
      DoubleData <$> (case endianness of
                        BigEndian    -> getDoublebe
                        LittleEndian -> getDoublele)

    TyFlt  endianness ->
      FloatData  <$> (case endianness of
                        BigEndian    -> getFloatbe
                        LittleEndian -> getFloatle)

    TyBuff siz ty -> ArrData <$> M.replicateM siz (getPrim ty)

    TyPrim prim -> Prim <$> getPrim prim

-- unwrap primitive data, shift to get bit offset, mask out higher bits, and wrap in primitive again
extractBits offset numBits ty prim =
  wrapPrim ty . mask numBits . (flip shiftR offset) . unwrapPrim $ prim

mask numBits bits = ((setBit zeroBits numBits) - 1) .&. bits

main =
  withFile "Logged_Data_20161219_1251_00_5m_altitude_sys.bin" ReadMode $ \hIn ->
  withFile "outFile.bin" WriteMode $ \hOut ->
    do runEffect $ (PB.hGet 206 hIn) >-> process >-> PB.toHandle hOut
       -- Pre.print $ decode sys

printSize :: Pipe PB.ByteString PB.ByteString IO r
printSize = PP.mapM (\a -> liftIO (Pre.print (B.length a)) >> return a)

process :: Pipe PB.ByteString PB.ByteString IO r
process = PP.mapM (\bytes -> Pre.print (retrieveSeq $ decomDef sys bytes) >> return bytes)

retrieveSeq decoded = findWithDefault (error "not found") "startTime" decoded

printer :: (Monad m, MonadIO m, Show a) => Pipe a a m r
printer = forever $ do
  a <- await
  liftIO $ Pre.print a
  yield a



