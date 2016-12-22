module CADH.Structures (
  PrimData(..),
  DataTree(..),
  Index,
  Struct,
  Field

) where

import Data.Tree
import Data.Map as M
import Data.Word
import Data.Int

import CADH.DataDefs


-- case studies:
--   locata variable length packets with blocks
--   data set ids in IA/HEU packets
--   single bit part of seq count is data set id for some IAM HS
--   telemetry stream with fixed or varying packet types
--   decoding array of fixed size structures

data DataTree a b
  = DataLeaf b
  | DataTree a [DataTree a b]


data IndexEntry = Field Sym Offset Size DataDef

type Index = DataTree IndexEntry ()
type Struct = DataTree IndexEntry PrimData


decodeDef :: DataDef -> Get Struct
decodeDef def = decodeDef' def 0

decodeDef def offset =
  case def of
    PackedDef    sym         defs -> decodePacked defs offset
    PackedBitDef sym         bitDefs -> decodeBits bitDefs offset
    OneOfDef     sym sym     mapping -> decodeOneOf mapping offset
    AllOfDef     sym         defs -> decodeAllOf defs offset
    ArrDef       sym arrSize def -> decodeArr arrSize def offset
    ValueDef     sym         val -> decodeVal offset val

decodePacked defs offset
decodeBits bitDefs offset
decodeOneOf mapping offset
decodeAllOf defs offset
decodeArr arrSize def offset
decodeVal offset val
