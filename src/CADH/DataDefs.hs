{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE UndecidableInstances #-}
module CADH.DataDefs
(
  Name,
  Endianness(..),
  Prim(..),
  PrimTy,
  PrimData,
  BasicTlm(..),
  BasicTy,
  BasicData,
  TlmTy(..),
  -- DataSet(..),
  Container(..),
  Tlm(..),
  TlmDef,
  TlmData,
  TlmDecoder,
  TlmDecoded,
  DecodeSection(..),
  Name,
  Size,
  Offset,
  wrapPrim,
  unwrapPrim,
  container,
  arrTlm,
  doubleTlm,
  doubleTlmle,
  doubleTlmbe,
  floatTlm,
  floatTlmle,
  floatTlmbe,
  uint8Tlm,
  sint8Tlm,
  uint16Tlm,
  sint16Tlm,
  uint16Tlmle,
  sint16Tlmbe,
  uint32Tlm,
  sint32Tlm,
  uint32Tlmle,
  sint32Tlmbe,
  uint64Tlm,
  sint64Tlm,
  uint64Tlmle,
  sint64Tlmbe,
  sizeOfBasic
) where

import Control.Monad.Identity

import qualified Data.Map as M
import Data.Word
import Data.Int
import qualified Data.Bimap as Bi
import Data.ByteString as B
import Data.Proxy


-- case studies:
--   locata variable length packets with blocks
--   data set ids in IA/HEU packets
--   single bit part of seq count is data set id for some IAM HS
--   telemetry stream with fixed or varying packet types
--   decoding array of fixed size structures

{- Data Definitions -}
type Name    = String
type Size    = Int
type Offset  = Int
type NumBits = Int

data ChecksumType
  = ChecksumOverflow
  | ChecksumUnderflow
  | ChecksumXOR
  deriving (Show, Eq)

data CRCType
  = CRCType32
  | CRCType16
  deriving (Show, Eq)

data Semantic a
  = SemanticTlmPoint
  | SemanticFixedValue a
  | SemanticChecksum ChecksumType
  | SemanticCRC CRCType
  deriving (Show, Eq)

data Endianness
  = BigEndian
  | LittleEndian
  deriving (Show, Eq, Enum)

data TlmTy a
  = TlmAny
  | TlmRequired a
  | TlmRequires Name a
  | TlmExpected a
  deriving (Show, Eq)

data EnumTy = EnumTy PrimTy (Bi.Bimap Int Name)

data Prim f
  = Uint8 (f Word8)
  | Uint16 Endianness  (f Word16)
  | Uint32 Endianness  (f Word32)
  | Uint64 Endianness  (f Word64)
  | Sint8              (f Int8)
  | Sint16  Endianness (f Int16)
  | Sint32  Endianness (f Int32)
  | Sint64  Endianness (f Int64)

deriving instance
  (Show (f Word8), Show (f Word16), Show (f Word32), Show (f Word64),
   Show (f Int8), Show (f Int16), Show (f Int32), Show (f Int64)) =>
  Show (Prim f)

deriving instance
  (Eq (f Word8), Eq (f Word16), Eq (f Word32), Eq (f Word64),
   Eq (f Int8), Eq (f Int16), Eq (f Int32), Eq (f Int64)) =>
  Eq (Prim f)

type PrimTy   = Prim TlmTy
type PrimData = Prim Identity

data BasicTlm f
  = TlmPrim   (Prim f)
  | TlmChar   (f Char)
  | TlmDbl    Endianness (f Double)
  | TlmFlt    Endianness (f Float)
  | TlmArray   Size  (Prim Proxy) [Prim f]
  | TlmBuff Size (f ByteString)
  | TlmBits   PrimTy Offset NumBits (Prim f)
  -- | TyEnum   EnumTy PrimTy

deriving instance
  (Show (f Word8), Show (f Word16), Show (f Word32), Show (f Word64),
   Show (f Int8), Show (f Int16), Show (f Int32), Show (f Int64),
   Show (f Char), Show (f Double), Show (f Float), Show (f ByteString)) =>
  Show (BasicTlm f)

deriving instance
  (Eq (f Word8), Eq (f Word16), Eq (f Word32), Eq (f Word64),
   Eq (f Int8), Eq (f Int16), Eq (f Int32), Eq (f Int64),
   Eq (f Char), Eq (f Double), Eq (f Float), Eq (f ByteString)) =>
  Eq (BasicTlm f)

type BasicTy = BasicTlm TlmTy
type BasicData = BasicTlm Identity


data Container = Buffer Name BasicTy
               | Section Name [Container]
               | AllOf Name [Container]
               -- | OneOf Name Name (M.Map Int Container)
               deriving (Show, Eq)

data Tlm a = Tlm 
  { tlmName    :: Name
  , tlmOffset  :: Offset 
  , tlmPayload :: a
  } deriving (Show, Eq)

type TlmDef     = Tlm BasicTy
type TlmData    = Tlm BasicData

data DecodeSection
  = DSDef TlmDef
  | DSChoice Name (M.Map PrimData DecodeSection)

-- FIXME this may not handle the VN-200 layout where the offsets depend on
-- the values of previous telemetry items
type TlmDecoder = M.Map Name DecodeSection
type TlmDecoded = M.Map Name TlmData

{- Convience functions -}
container nam children = Section nam children
arrTlm nam size ty = Buffer nam (TlmArray size ty [])

doubleTlm   nam endianness  = Buffer nam (TlmDbl endianness TlmAny)
doubleTlmle nam             = doubleTlm nam LittleEndian
doubleTlmbe nam             = doubleTlm nam BigEndian
floatTlm    nam  endianness = Buffer nam (TlmFlt endianness TlmAny)
floatTlmle  nam             = floatTlm nam LittleEndian
floatTlmbe  nam             = floatTlm nam BigEndian

uint8Tlm nam = Buffer nam (TlmPrim (Uint8 TlmAny))
sint8Tlm nam = Buffer nam (TlmPrim (Sint8 TlmAny))

uint16Tlm endianness nam = Buffer nam (TlmPrim (Uint16 endianness TlmAny))
sint16Tlm endianness nam = Buffer nam (TlmPrim (Sint16 endianness TlmAny))
uint16Tlmle = uint16Tlm LittleEndian
uint16Tlmbe = uint16Tlm BigEndian
sint16Tlmle = sint16Tlm LittleEndian
sint16Tlmbe = sint16Tlm BigEndian

uint32Tlm endianness nam = Buffer nam (TlmPrim (Uint32 endianness TlmAny))
sint32Tlm endianness nam = Buffer nam (TlmPrim (Sint32 endianness TlmAny))
uint32Tlmle = uint32Tlm LittleEndian
uint32Tlmbe = uint32Tlm BigEndian
sint32Tlmle = sint32Tlm LittleEndian
sint32Tlmbe = sint32Tlm BigEndian

uint64Tlm endianness nam = Buffer nam (TlmPrim (Uint64 endianness TlmAny))
sint64Tlm endianness nam = Buffer nam (TlmPrim (Sint64 endianness TlmAny))
uint64Tlmle = uint64Tlm LittleEndian
uint64Tlmbe = uint64Tlm BigEndian
sint64Tlmle = sint64Tlm LittleEndian
sint64Tlmbe = sint64Tlm BigEndian

{- Creating and using primitive data -}
wrapPrim (Uint8  _  ) n = Uint8    $ Identity $ toEnum n
wrapPrim (Uint16 e _) n = Uint16 e $ Identity $ toEnum n
wrapPrim (Uint32 e _) n = Uint32 e $ Identity $ toEnum n
wrapPrim (Uint64 e _) n = Uint64 e $ Identity $ toEnum n
wrapPrim (Sint8  _  ) n = Sint8    $ Identity $ toEnum n
wrapPrim (Sint16 e _) n = Sint16 e $ Identity $ toEnum n
wrapPrim (Sint32 e _) n = Sint32 e $ Identity $ toEnum n
wrapPrim (Sint64 e _) n = Sint64 e $ Identity $ toEnum n

unwrapPrim (Uint8    n) = fromEnum $ runIdentity n
unwrapPrim (Uint16 _ n) = fromEnum $ runIdentity n
unwrapPrim (Uint32 _ n) = fromEnum $ runIdentity n
unwrapPrim (Uint64 _ n) = fromEnum $ runIdentity n
unwrapPrim (Sint8    n) = fromEnum $ runIdentity n
unwrapPrim (Sint16 _ n) = fromEnum $ runIdentity n
unwrapPrim (Sint32 _ n) = fromEnum $ runIdentity n
unwrapPrim (Sint64 _ n) = fromEnum $ runIdentity n


--data BitData = BitData Name NumBits Endianness BasicTy

{-
type Subcom = M.Map Int DataDef

data DataDef
  = PackedDef        Name DataSize        [DataDef]  -- product
  | PackedBitDef     Name DataSize        [BitData]  -- product-like
  | OneOfDef         Name DataSize Name     Subcom    -- offer to packet
  | AllOfDef         Name DataSize        [DataDef]  -- request from packet
  | ArrDef           Name DataSize ArrSize DataDef   -- exponent, map from int/enum to datadef
  | ValueDef         Name DataSize         BasicTy   -- base type

data Structure = Leaf Name Offset BasicTy 
               | StructNode  Name Offset Size Structure
               | StructSeq   Name Offset Size [Structure]
               | StructBits  Name Offset Size [BitData]
               | StructMulti Name Offset Size [Structure]
-}
sizeOfBasic (TlmPrim  primTy)   = sizeOfPrim primTy
sizeOfBasic (TlmChar _)         = 1
sizeOfBasic (TlmDbl  _ _)       = 8
sizeOfBasic (TlmBits ty _ _ _)  = sizeOfPrim ty
sizeOfBasic (TlmFlt  _ _)       = 4
sizeOfBasic (TlmArray siz ty _) = siz * sizeOfPrim ty

sizeOfPrim (Uint8  _)   = 1
sizeOfPrim (Uint16 _ _) = 2
sizeOfPrim (Uint32 _ _) = 4
sizeOfPrim (Uint64 _ _) = 8
sizeOfPrim (Sint8  _)   = 1
sizeOfPrim (Sint16 _ _) = 2
sizeOfPrim (Sint32 _ _) = 4
sizeOfPrim (Sint64 _ _) = 8

{-
sizeOfStruct (StructNode  _ _ siz _) = siz
sizeOfStruct (StructSeq   _ _ siz _) = siz
sizeOfStruct (StructBits  _ _ siz _) = siz
sizeOfStruct (StructMulti _ _ siz _) = siz
sizeOfStruct (Leaf _ _ ty) = sizeOfBasic ty


sizeOfBits (BitData _ bits _ _) = bits
sizeOfBitDefs bits = ceiling . (/ 8) . sum . map sizeOfBits $ bits
-}

{-
decodeDef :: DataDef -> Get Structure
decodeDef def = runStateT 0 (decodeDef' def)

decodeDef' :: DataDef -> StateT Offset Get Structure
decodeDef' def =
  case def of
    PackedDef    sym         defs    -> decodePacked sym defs
    PackedBitDef sym         bitDefs -> decodeBits   sym bitDefs
    OneOfDef     sym sym     mapping -> decodeOneOf  sym mapping
    AllOfDef     sym         defs    -> decodeAllOf  sym defs
    ArrDef       sym arrSize def     -> decodeArr    sym arrSize def
    ValueDef     sym         val     -> decodeVal    sym val

decodePacked sym defs = 
  do offset <- get
     children <- mapM decodePacked defs
     return $ StructSeq sym offset (sum $ sizeof children) children

decodeBits  sym bitDefs =
  do offset <- get
     return $ StructBits sym offset (sizeOfBitDefs bitDefs) bitDefs

decodeOneOf sym mapping =
  do offset <- get
     return $ StructNode sym offset undefined -- need to deal with mapping

decodeAllOf sym defs =
  do offset <- get
     children <- decodeAtSameOffset defs
     return $ StructMulti sym offset (maximum $ map sizeOfStruct defs) children

decodeAtSameOffset []     = return []
decodeAtSameOffset (a:as) = 
  do offset <- get
    a' <- decodeDef' a
    put offset
    as' <- decodeAtSameOffset as
    return (a':as')

decodeArr sym arrSize def =
  do offset <- get
     children <- case arrSize of
                      SizeFixed siz  -> replicateM siz decodeDef'
                      SizeLookup sym -> undefined -- need to deal with mapping
     return $ StructSeq sym offset (sum $ map sizeOfStruct children) children

decodeVal sym def =
  do offset <- get
     return Leaf sym offset def

{- Example Definitions -}
ccsdsVersion       = BitData "Version"   3  BigEndian (TyPrim TyUint8)
ccsdsSecHeaderFlag = BitData "SecHeader" 1  BigEndian (TyPrim TyUint8)
ccsdsTypeFlag      = BitData "Type"      1  BigEndian (TyPrim TyUint8)
ccsdsApid          = BitData "APID"      11 BigEndian (TyPrim $ TyUint16 BigEndian)
-}

{-
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
-}
