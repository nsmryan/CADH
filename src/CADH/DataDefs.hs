module CADH.DataDefs
(
  Name,
  Endianness(..),
  PrimTy(..),
  PrimData(..),
  BasicTy(..),
  BasicData(..),
  ArrSize(..),
  -- DataSet(..),
  Container(..),
  Tlm(..),
  TlmDef,
  TlmData,
  TlmDecoder,
  TlmDecoded,
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

import qualified Data.Map as M
import Data.Word
import Data.Int
import qualified Data.Bimap as Bi


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

data Endianness = BigEndian
                | LittleEndian
                deriving (Show, Eq, Enum)

data EnumTy = EnumTy PrimTy (Bi.Bimap Int Name)

data PrimTy
  = TyUint8  
  | TyUint16 Endianness
  | TyUint32 Endianness
  | TyUint64 Endianness
  | TyInt8   
  | TyInt16  Endianness
  | TyInt32  Endianness
  | TyInt64  Endianness
  deriving (Show, Eq)

data BasicTy
  = TyPrim   PrimTy
  | TyChar
  | TyDbl    Endianness
  | TyFlt    Endianness
  -- | TyEnum   EnumTy PrimTy -- does not have a definite size
  | TyBuff   Size   PrimTy
  | TyBits   PrimTy Offset NumBits PrimTy
  -- | variable size buffer. unnamed array elements
  deriving (Show, Eq)

data PrimData
  = Uint8   Word8
  | Uint16  Word16
  | Uint32  Word32
  | Uint64  Word64
  | Sint8   Int8
  | Sint16  Int16
  | Sint32  Int32
  | Sint64  Int64
  -- string, array
  deriving (Show, Eq)

data BasicData
  = ArrData [PrimData]
  | Chr     Char
  | FloatData Float 
  | DoubleData Double 
  | Prim PrimData
  deriving (Show, Eq)
  -- | Enum    Int Name PrimTy


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

type TlmDecoder = M.Map Name TlmDef
-- type TlmDecoder = M.Map Name (Either TlmDef (Name, M.Map Int TlmDef))
type TlmDecoded = M.Map Name TlmData
data ArrSize = SizeFixed Size | SizeLookup Name

data DataSize = VariableSize | DataSize Size

container nam children = Section nam children
arrTlm nam size ty = Buffer nam (TyBuff size ty)

doubleTlm   nam endianness  = Buffer nam (TyDbl endianness)
doubleTlmle nam             = doubleTlm nam LittleEndian
doubleTlmbe nam             = doubleTlm nam BigEndian
floatTlm    nam  endianness = Buffer nam (TyFlt endianness)
floatTlmle  nam             = floatTlm nam LittleEndian
floatTlmbe  nam             = floatTlm nam BigEndian

uint8Tlm nam = Buffer nam (TyPrim TyUint8)
sint8Tlm nam = Buffer nam (TyPrim TyInt8)

uint16Tlm endianness nam = Buffer nam (TyPrim (TyUint16 endianness))
sint16Tlm endianness nam = Buffer nam (TyPrim (TyInt16 endianness))
uint16Tlmle nam = Buffer nam (TyPrim (TyUint16 LittleEndian))
sint16Tlmbe nam = Buffer nam (TyPrim (TyInt16 BigEndian))

uint32Tlm endianness nam = Buffer nam (TyPrim (TyUint32 endianness))
sint32Tlm endianness nam = Buffer nam (TyPrim (TyInt32 endianness))
uint32Tlmle nam = Buffer nam (TyPrim (TyUint32 LittleEndian))
sint32Tlmbe nam = Buffer nam (TyPrim (TyInt32 BigEndian))

uint64Tlm endianness nam = Buffer nam (TyPrim (TyUint64 endianness))
sint64Tlm endianness nam = Buffer nam (TyPrim (TyInt64 endianness))
uint64Tlmle nam = Buffer nam (TyPrim (TyUint64 LittleEndian))
sint64Tlmbe nam = Buffer nam (TyPrim (TyInt64 BigEndian))

wrapPrim  TyUint8     n = Uint8  $ toEnum n
wrapPrim (TyUint16 _) n = Uint16 $ toEnum n
wrapPrim (TyUint32 _) n = Uint32 $ toEnum n
wrapPrim (TyUint64 _) n = Uint64 $ toEnum n
wrapPrim  TyInt8      n = Sint8  $ toEnum n
wrapPrim (TyInt16  _) n = Sint16 $ toEnum n
wrapPrim (TyInt32  _) n = Sint32 $ toEnum n
wrapPrim (TyInt64  _) n = Sint64 $ toEnum n

unwrapPrim (Uint8  n) = fromEnum n
unwrapPrim (Uint16 n) = fromEnum n
unwrapPrim (Uint32 n) = fromEnum n
unwrapPrim (Uint64 n) = fromEnum n
unwrapPrim (Sint8  n) = fromEnum n
unwrapPrim (Sint16 n) = fromEnum n
unwrapPrim (Sint32 n) = fromEnum n
unwrapPrim (Sint64 n) = fromEnum n


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
sizeOfBasic (TyPrim  primTy) = sizeOfPrim primTy
sizeOfBasic (TyChar) = 1
sizeOfBasic (TyDbl _) = 8
sizeOfBasic (TyBits ty _ _ _) = sizeOfPrim ty
sizeOfBasic (TyFlt _) = 4
sizeOfBasic (TyBuff siz ty) = siz * sizeOfPrim ty

sizeOfPrim  TyUint8     = 1
sizeOfPrim (TyUint16 _) = 2
sizeOfPrim (TyUint32 _) = 4
sizeOfPrim (TyUint64 _) = 8
sizeOfPrim  TyInt8      = 1
sizeOfPrim (TyInt16  _) = 2
sizeOfPrim (TyInt32  _) = 4
sizeOfPrim (TyInt64  _) = 8

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
