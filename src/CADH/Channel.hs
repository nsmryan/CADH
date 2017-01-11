module CADH.Channel
  ( Channel(..)
  , DataFormat(..)
  , PacketSet(..)
  , ChannelType(..)
  , sinkChannel
  , sourceChannel
  ) where

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

import CADH.DataDefs


type FileName = String


-- many packets, same header with length
-- fixed length for all structures
-- length based on packet type field
-- length not known until decoding finished
data DataFormat
  = BinaryFormat PacketSet
  -- HexFormat
  | CSVFormat PacketDef Csv.HasHeader
  -- TableConfig
  -- LinesConfig

data PacketSet
  = PacketSetSingle PacketDef
  | PacketSetMany Name (M.Map Int Name) [PacketDef]
     
data Channel
  = Channel DataFormat ChannelType
  | EmptyChannel

data ChannelType
  = FileChannel FileName
  -- TCPChannel DataFormat Port IPAddress
  -- UDPChannel DataFormat Port IPAddress
  -- SerialChannel

sourceChannel :: Channel -> IO (Producer TlmDecoded IO ())
sourceChannel channel =
  case channel of
    (Channel (BinaryFormat packetSet) (FileChannel fileName)) ->
      case packetSet of
        PacketSetSingle (PacketDef _ container) ->
          do prod <- PB.fromHandle <$> openBinaryFile fileName ReadMode 
             return $ void $ parsed (decodeGet $ decommutate container) prod

    EmptyChannel ->
      return . forever . yield $ M.empty


sinkChannel :: Channel -> IO (Consumer TlmDecoded IO r)
sinkChannel channel =
  case channel of
    Channel format (FileChannel fileName) ->
      do fh <- openBinaryFile fileName WriteMode 
         let preprocess = case format of
                            BinaryFormat (PacketSetSingle (PacketDef _ container)) ->
                              PP.map (toStrict . runPut . recommutate container)
                        
                            CSVFormat (PacketDef _ container) hasHeader ->
                              PCsv.encodeByName (containerCSVHeader container)
         return $ preprocess >-> PB.toHandle fh

    EmptyChannel ->
      return drain

