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

data PrimData
  = Uint8   Word8
  | Uint16  Word16
  | Uint32  Word32
  | Uint64  Word64
  | Sint8   Int8
  | Sint16  Int16
  | Sint32  Int32
  | Sint64  Int64
  | Chr     Char
  | Flt     Float 
  | Dbl     Double 
  | Enum    Sym
  -- string, array

data DataTree a
  = DataLeaf a
  | DataTree a [DataTree a]

type Offset = Int
type Size = Int

data Field = Field Offset Size DataDef

type Index = DataTree Field

type Struct = Map Sym PrimData

tlmStuct = M.fromList [("Apid", 1), ("Version", 0), ("SecHeaderFlag", 1), ("Type", 1)]

