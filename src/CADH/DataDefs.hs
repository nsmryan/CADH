module CADH.DataDefs
(
  Sym,
  Endianness(..),
  PrimTy(..),
  DataDef(..),
  BasicTy(..),
  ArrSize(..),
  DataSet(..),
  BitData(..)
) where

import Data.Map as M
import Data.Word
import Data.Int
import Data.Bimap as Bi


-- case studies:
--   locata variable length packets with blocks
--   data set ids in IA/HEU packets
--   single bit part of seq count is data set id for some IAM HS
--   telemetry stream with fixed or varying packet types
--   decoding array of fixed size structures

{- Data Definitions -}
type Sym = String

data Endianness = BigEndian | LittleEndian

data EnumTy = EnumTy PrimTy (Bi.Bimap Int Sym)

data PrimTy
  = TyUint8  
  | TyUint16 Endianness
  | TyUint32 Endianness
  | TyUint64 Endianness
  | TyInt8   
  | TyInt16  Endianness
  | TyInt32  Endianness
  | TyInt64  Endianness

data BasicTy
  = TyPrim   PrimTy
  | TyChar
  | TyDbl    Endianness
  | TyFlt    Endianness
  | TyEnum   EnumTy PrimTy
  -- | fixed size byte buffer. unnamed array elements
  
data ArrSize = SizeFixed Int | SizeLookup Sym

type DataSet = M.Map BasicTy DataDef


type NumBits = Int

data BitData = BitData Sym NumBits Endianness BasicTy

data DataDef
  = PackedDef        Sym         [DataDef]  -- product
  | PackedBitDef     Sym         [BitData]  -- product-like
  | OneOfDef         Sym Sym      DataSet   -- offer to packet
  | AllOfDef         Sym         [DataDef]  -- request from packet
  | ArrDef           Sym ArrSize  DataDef   -- exponent, map from int/enum to datadef
  | ValueDef         Sym          BasicTy   -- base type

{- Example Definitions -}
ccsdsVersion       = BitData "Version"   3  BigEndian (TyPrim TyUint8)
ccsdsSecHeaderFlag = BitData "SecHeader" 1  BigEndian (TyPrim TyUint8)
ccsdsTypeFlag      = BitData "Type"      1  BigEndian (TyPrim TyUint8)
ccsdsApid          = BitData "APID"      11 BigEndian (TyPrim $ TyUint16 BigEndian)

priHeader =
  PackedBitDef "PriHeader" 
  [  ccsdsVersion
  ,  ccsdsSecHeaderFlag
  ,  ccsdsTypeFlag
  ,  ccsdsApid
  ]

secHeaderSeconds       = BitData "Version"   3  BigEndian (TyPrim TyUint8)
secHeaderSubseconds    = BitData "SecHeader" 1  BigEndian (TyPrim TyUint8)
secHeaderFlagsChecksum = BitData "Checksum"  1  BigEndian (TyPrim TyUint8)
secHeaderFlagsPad      = BitData "pad"       15 BigEndian (TyPrim $ TyUint16 BigEndian)

secHeader =
  PackedBitDef "SecHeader" 
  [  secHeaderSeconds
  ,  secHeaderSubseconds
  ,  secHeaderFlagsChecksum
  ,  secHeaderFlagsPad
  ]

header = PackedDef "Header" [priHeader, secHeader]

checksum = ValueDef "checksum" (TyPrim $ TyUint16 BigEndian)

tlmData = ArrDef "HSData" (SizeFixed 542) (ValueDef "hsDataByte" (TyPrim TyUint8))
smartTlm = PackedDef "HS" [header, tlmData, checksum]

