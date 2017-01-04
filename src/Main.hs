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
import Data.Proxy
import Data.Either

import Control.Monad as M
import Control.Monad.Identity
import Control.Applicative

import System.IO

import CADH.DataDefs


type Decom a = Either String a

priHeader endianness =
  Section "PriHeader" [ firstWord endianness
                      , seqWord endianness
                      , uint16Tlm endianness "Length"
                      ]

firstWord endianness =
  let withinType = Uint16 endianness TlmAny
   in AllOf "PriHeaderFirstWord" [ Buffer "APID"          (TlmBits withinType 0 11 (Uint16 endianness (TlmRequired 3)))
                                 , Buffer "SecHeaderFlag" (TlmBits withinType 11 1 (Uint8 TlmAny))
                                 , Buffer "PacketType"    (TlmBits withinType 12 1 (Uint8 TlmAny))
                                 , Buffer "CCSDSVersion"  (TlmBits withinType 13 3 (Uint8 TlmAny))
                                 ]
seqWord endianness = 
  let withinType = Uint16 endianness TlmAny in 
    AllOf "Seq" [ Buffer "SeqFlag"  (TlmBits withinType 14  2 (Uint8 TlmAny))
                , Buffer "SeqCount" (TlmBits withinType  0 14 (Uint16 endianness TlmAny))
                ]
 
secHeader endianness = Buffer "SecHeader" (TlmArray 10 (Uint8 Proxy) [])
ccsdsHeader endianness = Section "CCSDSHeader" [priHeader endianness, secHeader endianness]

dataBuffer =
  container "SystemState" [arrTlm "Data" 108 (Uint8 Proxy)]

checksum = Buffer "Checksum" (TlmPrim (Uint16 LittleEndian TlmAny))

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
      (M.insert nam (DSDef $ Tlm nam offset ty) map, offset + sizeOfBasic ty)

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
  in case tlmDecoder of
       DSDef tlmDecoder ->
        M.foldl insertDecommed M.empty tlmDecoder

       DSChoice nam choice ->
         undefined

decomTlm :: TlmDef -> PB.ByteString -> TlmData
decomTlm (Tlm nam offset ty) bytes =
  let decomData = decomBasic ty $ B.drop offset bytes
  in Tlm nam offset decomData

decomBasic :: BasicTy -> PB.ByteString -> BasicData 
decomBasic ty bytes =
  case getBasic ty of
    Left err -> error err
    Right getBas -> runGet getBas (BL.fromStrict bytes)

getPrim :: Prim f -> Decom (Get PrimData)
getPrim ty = 
  Right $ case ty of
    Uint8 _ ->
      (Uint8 . Identity) <$> getWord8

    Uint16 e _ ->
      fmap (Uint16 e . Identity)
           (case e of
              BigEndian    -> getWord16be
              LittleEndian -> getWord16le)

    Uint32 e _ ->
      fmap (Uint32 e . Identity)
           (case e of
              BigEndian    -> getWord32be
              LittleEndian -> getWord32le)

    Uint64 e _ ->
      fmap (Uint64 e . Identity) 
           (case e of
              BigEndian    -> getWord64be
              LittleEndian -> getWord64le)

    Sint8 _ ->
      fmap (Sint8 . Identity)
            getInt8

    Sint16 e _ ->
      fmap (Sint16 e . Identity)
           (case e of
              BigEndian    -> getInt16be
              LittleEndian -> getInt16le)

    Sint32  e _ ->
      fmap (Sint32 e . Identity)
           (case e of
              BigEndian    -> getInt32be
              LittleEndian -> getInt32le)

    Sint64 e _ ->
      fmap (Sint64 e . Identity)
           (case e of
              BigEndian    -> getInt64be
              LittleEndian -> getInt64le)

getBasic :: BasicTy -> Decom (Get BasicData)
getBasic ty = 
  case ty of
    TlmChar _ ->
      Right $ (TlmChar . Identity . toEnum . fromEnum) <$> getWord8

    TlmBits tyWithin offset numBits ty ->
      (fmap . fmap) (TlmPrim . extractBits offset numBits ty) 
                    (getPrim tyWithin)

    TlmDbl e _ ->
      Right $ fmap (TlmDbl e . Identity)
                   (case e of
                      BigEndian    -> getDoublebe
                      LittleEndian -> getDoublele)

    TlmFlt e _ ->
      Right $ fmap (TlmFlt e . Identity)
                   (case e of
                      BigEndian    -> getFloatbe
                      LittleEndian -> getFloatle)

    TlmArray siz ty _ ->
      Right $ fmap (TlmArray siz ty) 
                   (Pre.sequence . rights . Pre.replicate siz $ (getPrim ty))

    TlmPrim prim ->
      (fmap . fmap) TlmPrim $ getPrim prim

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



