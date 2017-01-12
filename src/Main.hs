{-# LANGUAGE OverloadedStrings #-}
module Main where

import Prelude as Pre

import Pipes.ByteString as PB
import Pipes.Binary
import Pipes as P
import Pipes.Prelude as PP
import Pipes.Parse as Parse
import qualified Pipes.Csv as PCsv

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
import qualified Data.Csv as Csv
import qualified Data.Vector as V

import Control.Monad as M
import Control.Monad.Identity
import Control.Applicative

import System.IO
import System.FilePath

import Options.Applicative as Opt

import CADH.DataDefs
import CADH.Channel


ccsdsPacketIdentifier :: PacketSet
ccsdsPacketIdentifier = PacketSetSingle ccsdsPacketDef

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
  TlmPoint "CCSDSDataBuffer" (TlmBuff (VariableSize "CCSDSLength" (-1)) TlmAny) Nothing

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
               [ TlmPoint "APID"          (TlmBits withinType 0 11 (Uint16 endianness TlmAny)) Nothing
               , TlmPoint "SecHeaderFlag" (TlmBits withinType 11 1 (Uint8 TlmAny)) Nothing
               , TlmPoint "PacketType"    (TlmBits withinType 12 1 (Uint8 TlmAny)) Nothing
               , TlmPoint "CCSDSVersion"  (TlmBits withinType 13 3 (Uint8 TlmAny)) Nothing
               ]

seqWord :: Endianness -> Container
seqWord endianness = 
  let withinType = Uint16 endianness TlmAny in 
    bitField "Seq"
             withinType
             [ TlmPoint "SeqFlag"  (TlmBits withinType 14  2 (Uint8 TlmAny)) Nothing
             , TlmPoint "SeqCount" (TlmBits withinType  0 14 (Uint16 endianness TlmAny)) Nothing
             ]
 
secHeader endianness = TlmPoint "SecHeader" (TlmArray (FixedSize 10) (Uint8 Proxy) []) Nothing
ccsdsHeader endianness = Section "CCSDSHeader" [priHeader endianness, secHeader endianness]

dataBuffer =
  container "SystemState" [arrTlm "Data" 108 (Uint8 Proxy)]

ccsdsChecksum = TlmPoint "CCSDSChecksum" (TlmPrim (Uint16 LittleEndian TlmAny)) (Just SemanticChecksum)

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

testSource = Channel (BinaryFormat (PacketSetSingle systemStatePacket))
                     (FileChannel "Logged_Data_20161219_1251_00_5m_altitude_sys.bin")
                     --(FileChannel "Logged_Data_20161216_1705_00_Fourth_Attempt_Full_Grid")

binaryChannel fileName = 
  Channel (BinaryFormat (PacketSetSingle ccsdsPacketDef))
          (FileChannel fileName)

csvChannel fileName = 
  Channel (CSVFormat ccsdsPacketDef Csv.HasHeader)
          (FileChannel fileName)

testSink = Channel (CSVFormat systemStatePacket Csv.HasHeader) (FileChannel "outFile.bin")


printSize :: Pipe PB.ByteString PB.ByteString IO r
printSize = PP.mapM (\a -> liftIO (Pre.print (B.length a)) >> return a)

process :: Producer PB.ByteString IO r ->
           PacketSet ->
           Producer TlmDecoded IO (DecodingError, Producer PB.ByteString IO r)
process prod (PacketSetSingle (PacketDef name container)) =
  parsed (decodeGet . decommutate $ container) prod

process _ _ = error "PacketSetMany not implemented"

retrieveTlm :: Name -> Pipe TlmDecoded TlmData IO r
retrieveTlm tlmName = 
  PP.map $ M.findWithDefault (error $ tlmName ++ " count not found") tlmName

printer :: (Monad m, MonadIO m, Show a) => Pipe a a m r
printer = forever $ do
  a <- await
  liftIO $ Pre.print a
  yield a

data CADHConfig
  = CADHConfig

{-
   FIXME add commands-
     decom [binary|csv|hex] [split|combine]
 -}
cadhMain inputFile outputFile = do
  let src = case takeExtension inputFile of
              ".csv"    -> csvChannel    inputFile
              ".txt"    -> csvChannel    inputFile
              ".bin"    -> binaryChannel inputFile
              otherwise -> binaryChannel inputFile
  let snk = case takeExtension outputFile of
              ".csv"    -> csvChannel     outputFile
              ".txt"    -> csvChannel     outputFile
              ".bin"    -> binaryChannel  outputFile
              otherwise -> binaryChannel  outputFile
  source <- sourceChannel src
  sink   <- sinkChannel snk
  runEffect $ source >->
              -- retrieveTlm "APID" >->
              -- printer >->
              -- PP.map (toStrict . runPut . recommutate ccsdsPacketContainer) >->
              sink
main :: IO ()
main = join . execParser $
  info (helper <*> parser)
  (  fullDesc
  <> header "Command and Data Handling (CADH)"
  <> progDesc "CADH is a program for processing telemetry files"
  )
  where
    parser :: Opt.Parser (IO ())
    parser =
      cadhMain
        <$> strOption
            (  long "input-file"
            <> short 'f'
            <> metavar "INPUTFILE"
            <> help "input telemetry file"
            <> value  "Logged_Data_20161219_1251_00_5m_altitude_sys.bin"
            )
        <*> strOption
            (  long "output-file"
            <> short 'o'
            <> metavar "OUTPUTFILE"
            <> help "output telemetry file"
            <> value "outFile.csv"
            )
