{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}

module CADH.DataDefs
(
  -- Simple types
  Name,
  Endianness(..),
  Size(..),
  Offset,
  -- Primitive data
  Prim(..),
  PrimTy,
  PrimData,
  wrapPrim,
  unwrapPrim,
  endian,
  -- Basic Data
  BasicTlm(..),
  BasicTy,
  BasicData,
  sizeOfBasic,
  -- Telemetry
  TlmTy(..),
  -- DataSet(..),
  Container(..),
  Tlm(..),
  TlmDef,
  TlmData,
  TlmDecoded,
  PacketDef(..),
  containerCSVHeader,
  sizeOfContainer,
  printTlmPoint,
  Semantic(..),
  ChecksumType(..),
  CRCType(..),
  -- Decom/Recom packets
  decommutate,
  decomOrError,
  recommutate,
  recommutateTlmPoint,
  recommutatePrim,
  -- Constructing telemetry packets
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
  bitField,
  sint64Tlmbe
) where

import Prelude as Pre

import qualified Data.Map as M
import qualified Data.Bimap as Bi
import qualified Data.ByteString.Lazy as BL
import qualified Data.Csv as Csv
import qualified Data.Vector as V
import Data.ByteString as B
import Data.ByteString.Char8 as BChar
import Data.ByteString.Builder as BB
import Data.Foldable as F
import Data.List as L
import Data.Bits
import Data.Maybe
import Data.Word
import Data.Proxy
import Data.Binary
import Data.Binary.Put
import Data.Binary.Get
import Data.Int
import Data.Either.Validation
import Data.Monoid

import Control.Monad.Identity
import Control.Monad.Trans.Either
import Control.Monad.Trans.Class
import Control.Monad as M

import Hexdump


-- case studies:
--   locata variable length packets with blocks
--   data set ids in IA/HEU packets
--   single bit part of seq count is data set id for some IAM HS
--   telemetry stream with fixed or varying packet types
--   decoding array of fixed size structures

{- Data Definitions -}
type Name    = String
type Offset  = Int
type NumBits = Int

type Decom a = EitherT TlmValidationError Get a

failedDecom validationError = EitherT $ return $ Left validationError

data TlmValidationError
  = TlmValidationChecksumError Name PrimData PrimData ByteString
  | TlmValidationValueError Name PrimData PrimData
  -- TlmValidationConditionError PrimData -- failed to satisfy condition

instance Show TlmValidationError where
  show (TlmValidationChecksumError name primData primData' byteString) =
    show name ++ ": was " ++ show primData ++ ", expected " ++ show primData' ++ "\nbytes (" ++ show (B.length byteString) ++ "):\n" ++ simpleHex byteString

  show (TlmValidationValueError name required actual) =
    show name ++ " was " ++ show actual ++ " but should have been " ++ show required

data Size
  = FixedSize Int
  | VariableSize Name Int
  deriving (Show, Eq, Ord)

data ChecksumType
  = ChecksumOverflow
  | ChecksumUnderflow
  -- | ChecksumXOR -- FIXME needs a Bits instance for PrimData
  deriving (Show, Eq)

data CRCType
  = CRCType32
  | CRCType16
  deriving (Show, Eq)

data Semantic
  = SemanticRequired (PrimData)
  | SemanticChecksum Name ChecksumType
  | SemanticCRC CRCType
  | SemanticExpected (PrimData)
  | SemanticLength Int
  -- | SemanticCondition TlmExpr
  deriving (Show, Eq)

data Limit a
  = LTLimit a
  | GTLimit a
  | WithinRange a a
  | EqLimit a
  | InSetLimit [a]
  | AndLimit (Limit a) (Limit a)
  | OrLimit (Limit a) (Limit a)
  | NotLimit (Limit a) (Limit a)
  | ImpliesLimit (Limit a) (Limit a)
  -- | LimitConst a
  -- | LimitVar Name

{-
data TlmExpr
  = TlmExprIf TlmExpr TlmExpr
  | TlmExprIfThen TlmExpr TlmExpr TlmExpr
  | TlmExprAnd TlmExpr TlmExpr
  | TlmExprOr TlmExpr TlmExpr
  | TlmExprNot TlmExpr
  | TlmExprImplies TlmExpr TlmExpr
  | TlmExprSum TlmExpr TlmExpr
  | TlmExprDiff TlmExpr TlmExpr
  | TlmExprProd TlmExpr TlmExpr
  | TlmExprQuot TlmExpr TlmExpr
  | TlmExprBitSet TlmExpr TlmExpr
  | TlmExprBitMask TlmExpr TlmExpr
  | TlmExprConstant PrimData
  | TlmExprVar Name
-}

data Persistence
  = PersistPacketCount Int
  | PersistTime Double

data Severity
  = SeverityInformational
  | SeverityWarning
  | SeverityError

data TlmLimitDef a = TlmLimitDef
  { tlmLimitName :: Name
  , tlmLimit :: Limit a
  , tlmLimitPersistence :: Persistence
  , tlmLimitSeverity :: Severity
  }

data TlmLimitData a = TlmLimitData
  { tlmLimitDef :: TlmLimitDef a
  , tlmLimitCount :: Persistence
  }

data Endianness
  = BigEndian
  | LittleEndian
  deriving (Show, Eq, Enum, Ord)

data TlmTy a
  = TlmAny
  | TlmRequired a
  | TlmRequires Name a
  | TlmExpected a
  deriving (Show, Eq, Ord)

data EnumTy = EnumTy PrimTy (Bi.Bimap Int Name)

data TlmPhaseType = TlmPhaseType 
data TlmPhaseData = TlmPhaseData

type family TlmPhase id a
type instance TlmPhase TlmPhaseData a = a
type instance TlmPhase TlmPhaseType a = TlmTy a

data Prim phase
  = Uint8             (TlmPhase phase Word8)
  | Uint16 Endianness (TlmPhase phase Word16)
  | Uint32 Endianness (TlmPhase phase Word32)
  | Uint64 Endianness (TlmPhase phase Word64)
  | Sint8             (TlmPhase phase Int8)
  | Sint16 Endianness (TlmPhase phase Int16)
  | Sint32 Endianness (TlmPhase phase Int32)
  | Sint64 Endianness (TlmPhase phase Int64)

deriving instance Show (Prim TlmPhaseData)
deriving instance Show (Prim TlmPhaseType)

deriving instance Eq (Prim TlmPhaseData)
deriving instance Eq (Prim TlmPhaseType)

deriving instance Ord (Prim TlmPhaseType)
deriving instance Ord (Prim TlmPhaseData)

instance Num (Prim TlmPhaseData) where
  prim1 + prim2 =
    case (prim1, prim2) of
      (Uint8    n, Uint8     n') -> Uint8    (n + n')
      (Uint16 e n, Uint16 e' n') -> Uint16 e (n + n')
      (Uint32 e n, Uint32 e' n') -> Uint32 e (n + n')
      (Uint64 e n, Uint64 e' n') -> Uint64 e (n + n')
      (Sint8    n, Sint8     n') -> Sint8    (n + n')
      (Sint16 e n, Sint16 e' n') -> Sint16 e (n + n')
      (Sint32 e n, Sint32 e' n') -> Sint32 e (n + n')
      (Sint64 e n, Sint64 e' n') -> Sint64 e (n + n')
      otherwise -> error $ "Cannot apply binary operator to " ++ show prim1 ++ ", and " ++ show prim2
  prim1 - prim2 =
    case (prim1, prim2) of
      (Uint8    n, Uint8     n') -> Uint8    (n - n')
      (Uint16 e n, Uint16 e' n') -> Uint16 e (n - n')
      (Uint32 e n, Uint32 e' n') -> Uint32 e (n - n')
      (Uint64 e n, Uint64 e' n') -> Uint64 e (n - n')
      (Sint8    n, Sint8     n') -> Sint8    (n - n')
      (Sint16 e n, Sint16 e' n') -> Sint16 e (n - n')
      (Sint32 e n, Sint32 e' n') -> Sint32 e (n - n')
      (Sint64 e n, Sint64 e' n') -> Sint64 e (n - n')
      otherwise -> error $ "Cannot apply binary operator to " ++ show prim1 ++ ", and " ++ show prim2
  prim1 * prim2 =
    case (prim1, prim2) of
      (Uint8    n, Uint8     n') -> Uint8    (n * n')
      (Uint16 e n, Uint16 e' n') -> Uint16 e (n * n')
      (Uint32 e n, Uint32 e' n') -> Uint32 e (n * n')
      (Uint64 e n, Uint64 e' n') -> Uint64 e (n * n')
      (Sint8    n, Sint8     n') -> Sint8    (n * n')
      (Sint16 e n, Sint16 e' n') -> Sint16 e (n * n')
      (Sint32 e n, Sint32 e' n') -> Sint32 e (n * n')
      (Sint64 e n, Sint64 e' n') -> Sint64 e (n * n')
      otherwise -> error $ "Cannot apply binary operator to " ++ show prim1 ++ ", and " ++ show prim2
  abs prim =
    case prim of
      Uint8    n -> Uint8    $ abs n
      Uint16 e n -> Uint16 e $ abs n
      Uint32 e n -> Uint32 e $ abs n
      Uint64 e n -> Uint64 e $ abs n
      Sint8    n -> Sint8    $ abs n
      Sint16 e n -> Sint16 e $ abs n
      Sint32 e n -> Sint32 e $ abs n
      Sint64 e n -> Sint64 e $ abs n
  negate prim =
    case prim of
      Uint8    n -> Uint8    $ negate n
      Uint16 e n -> Uint16 e $ negate n
      Uint32 e n -> Uint32 e $ negate n
      Uint64 e n -> Uint64 e $ negate n
      Sint8    n -> Sint8    $ negate n
      Sint16 e n -> Sint16 e $ negate n
      Sint32 e n -> Sint32 e $ negate n
      Sint64 e n -> Sint64 e $ negate n
  signum prim =
    case prim of
      Uint8    n -> Uint8    $ 1
      Uint16 e n -> Uint16 e $ 1
      Uint32 e n -> Uint32 e $ 1
      Uint64 e n -> Uint64 e $ 1
      Sint8    n -> Sint8    $ signum n
      Sint16 e n -> Sint16 e $ signum n
      Sint32 e n -> Sint32 e $ signum n
      Sint64 e n -> Sint64 e $ signum n
  fromInteger n = Sint64 LittleEndian $ fromIntegral n
  

type PrimTy    = Prim TlmPhaseType
type PrimData  = Prim TlmPhaseData

data BasicTlm tlmPhase
  = TlmPrim   (Prim tlmPhase)
  | TlmChar   (TlmPhase tlmPhase Char)
  | TlmDbl    Endianness (TlmPhase tlmPhase Double)
  | TlmFlt    Endianness (TlmPhase tlmPhase Float)
  | TlmArray  Size  (Prim TlmPhaseType) [Prim tlmPhase]
  | TlmBuff   Size (TlmPhase tlmPhase ByteString)
  | TlmBits   PrimTy Offset NumBits (Prim tlmPhase)
  -- | TyEnum   EnumTy PrimTy

type BasicTy    = BasicTlm TlmPhaseType
type BasicData  = BasicTlm TlmPhaseData

deriving instance Show BasicTy
deriving instance Show BasicData

deriving instance Eq BasicTy
deriving instance Eq BasicData

--deriving instance
--  (Show (f Word8), Show (f Word16), Show (f Word32), Show (f Word64),
--   Show (f Int8), Show (f Int16), Show (f Int32), Show (f Int64),
--   Show (f Char), Show (f Double), Show (f Float), Show (f ByteString)) =>
--  Show (BasicTlm f)
--
--deriving instance
--  (Eq (f Word8), Eq (f Word16), Eq (f Word32), Eq (f Word64),
--   Eq (f Int8), Eq (f Int16), Eq (f Int32), Eq (f Int64),
--   Eq (f Char), Eq (f Double), Eq (f Float), Eq (f ByteString)) =>
--  Eq (BasicTlm f)

data EmptyAllowed = EmptyAllowed | EmptyNotAllowed
  deriving (Show, Eq, Ord, Enum)

data Container
  = TlmPoint Name BasicTy (Maybe Semantic)
  | Section Name [Container]
  | AllOf Name [Container]
  | OneOf Name Name (M.Map Int Container) EmptyAllowed
  deriving (Show, Eq)

data Tlm a = Tlm
  { tlmName    :: Name
  , tlmOffset  :: Offset
  , tlmPayload :: a
  } deriving (Show, Eq)

data PacketDef = PacketDef
  { packetName :: Name
  , packetDef :: Container
  }

instance (Csv.ToField a) => Csv.ToField (Tlm a) where
  toField tlm = Csv.toField $ tlmPayload tlm

-- instance Csv.ToNamedRecord TlmData where
--   toNamedRecord tlmData = Csv.toNamedRecord $ tlmPayload tlmData
--
-- instance Csv.ToNamedRecord BasicData where
--   toNamedRecord tlmData = undefined -- Csv.toNamedRecord $ tlmPayload tlmData

instance Csv.ToField BasicData where
  toField basicData =
    BL.toStrict $ toLazyByteString $
      case basicData of
        TlmPrim   prim ->
          byteString $ Csv.toField prim

        TlmChar chr ->
          char8 chr

        TlmDbl e dbl ->
          doubleDec dbl

        TlmFlt e flt ->
          floatDec flt

        TlmArray size prim prims ->
          byteString $ F.fold $ L.intersperse (BChar.singleton ' ') $ Pre.map Csv.toField prims

        TlmBuff size bytes ->
          byteStringHex bytes

        TlmBits primty offset numBits prim ->
          byteString $ Csv.toField prim

instance Csv.ToField PrimData where
  toField primData =
    BL.toStrict $ toLazyByteString $
      case primData of
        Uint8 n ->
          word8Dec n

        Uint16 e n ->
          word16Dec n

        Uint32 e n ->
          word32Dec n

        Uint64 e n ->
          word64Dec n

        Sint8 n ->
          int8Dec n

        Sint16 e n ->
          int16Dec n

        Sint32 e n ->
          int32Dec n

        Sint64 e n ->
          int64Dec n

primOp1 uint8Op uint16Op uint32Op uint64Op int8Op int16Op int32Op int64Op primData =
  case primData of
    Uint8 n ->
      uint8Op n

    Uint16 e n ->
      uint16Op n

    Uint32 e n ->
      uint32Op n

    Uint64 e n ->
      uint64Op n

    Sint8 n ->
      int8Op n

    Sint16 e n ->
      int16Op n

    Sint32 e n ->
      int32Op n

    Sint64 e n ->
      int64Op n

containerCSVHeader :: Container -> Csv.Header
containerCSVHeader container = V.fromList $ Pre.map BChar.pack $ containerCSVHeader' container

containerCSVHeader' :: Container -> [String]
containerCSVHeader' container =
  case container of
    TlmPoint name ty _ ->
      [name]

    Section name children ->
      Pre.concatMap containerCSVHeader' children

    AllOf name children ->
      Pre.concatMap containerCSVHeader' children

    OneOf name key map _ ->
      Pre.concatMap containerCSVHeader' $ M.elems map

printBasic basic =
  case basic of
    TlmPrim prim ->
      show prim

    TlmChar chr ->
      show chr

    TlmDbl e dbl ->
      show dbl

    TlmFlt e flt ->
      show flt

    TlmArray siz  prim prims ->
      show prims

    TlmBuff siz bytes ->
      show $ fmap simpleHex bytes

    TlmBits primContainer offset n prim ->
      show prim

printTlmPoint (Tlm name offset payload)
  = name ++ ": " ++ printBasic payload ++ " at offset " ++ show offset

type TlmDef     = Tlm BasicTy
type TlmData    = Tlm BasicData

-- FIXME this needs metadata- packet time, source name, byte offset, line/packet count
type TlmDecoded = M.Map Name TlmData

{- Convience functions -}
container nam children = Section nam children
arrTlm nam sz ty = TlmPoint nam (TlmArray (FixedSize sz) ty []) Nothing
arrTlmVariable nam szName ty = TlmPoint nam (TlmArray (VariableSize szName 0) ty [])

doubleTlm   nam endianness  = TlmPoint nam (TlmDbl endianness TlmAny) Nothing
doubleTlmle nam             = doubleTlm nam LittleEndian
doubleTlmbe nam             = doubleTlm nam BigEndian
floatTlm    nam  endianness = TlmPoint nam (TlmFlt endianness TlmAny) Nothing
floatTlmle  nam             = floatTlm nam LittleEndian
floatTlmbe  nam             = floatTlm nam BigEndian

uint8Tlm nam = TlmPoint nam (TlmPrim (Uint8 TlmAny)) Nothing
sint8Tlm nam = TlmPoint nam (TlmPrim (Sint8 TlmAny)) Nothing

uint16Tlm endianness nam = TlmPoint nam (TlmPrim (Uint16 endianness TlmAny)) Nothing
sint16Tlm endianness nam = TlmPoint nam (TlmPrim (Sint16 endianness TlmAny)) Nothing
uint16Tlmle = uint16Tlm LittleEndian
uint16Tlmbe = uint16Tlm BigEndian
sint16Tlmle = sint16Tlm LittleEndian
sint16Tlmbe = sint16Tlm BigEndian

uint32Tlm endianness nam = TlmPoint nam (TlmPrim (Uint32 endianness TlmAny)) Nothing
sint32Tlm endianness nam = TlmPoint nam (TlmPrim (Sint32 endianness TlmAny)) Nothing
uint32Tlmle = uint32Tlm LittleEndian
uint32Tlmbe = uint32Tlm BigEndian
sint32Tlmle = sint32Tlm LittleEndian
sint32Tlmbe = sint32Tlm BigEndian

uint64Tlm endianness nam = TlmPoint nam (TlmPrim (Uint64 endianness TlmAny)) Nothing
sint64Tlm endianness nam = TlmPoint nam (TlmPrim (Sint64 endianness TlmAny)) Nothing
uint64Tlmle = uint64Tlm LittleEndian
uint64Tlmbe = uint64Tlm BigEndian
sint64Tlmle = sint64Tlm LittleEndian
sint64Tlmbe = sint64Tlm BigEndian


bitField name withinType bitTlmPoints
  = AllOf (name ++ "Group") $ (TlmPoint (name ++ "Field") (TlmPrim withinType) Nothing) : bitTlmPoints

{- Creating and using primitive data -}
wrapPrim (Uint8  _  ) n = Uint8    $ toEnum n
wrapPrim (Uint16 e _) n = Uint16 e $ toEnum n
wrapPrim (Uint32 e _) n = Uint32 e $ toEnum n
wrapPrim (Uint64 e _) n = Uint64 e $ toEnum n
wrapPrim (Sint8  _  ) n = Sint8    $ toEnum n
wrapPrim (Sint16 e _) n = Sint16 e $ toEnum n
wrapPrim (Sint32 e _) n = Sint32 e $ toEnum n
wrapPrim (Sint64 e _) n = Sint64 e $ toEnum n

unwrapPrim (Uint8    n) = fromEnum n
unwrapPrim (Uint16 _ n) = fromEnum n
unwrapPrim (Uint32 _ n) = fromEnum n
unwrapPrim (Uint64 _ n) = fromEnum n
unwrapPrim (Sint8    n) = fromEnum n
unwrapPrim (Sint16 _ n) = fromEnum n
unwrapPrim (Sint32 _ n) = fromEnum n
unwrapPrim (Sint64 _ n) = fromEnum n


--data BitData = BitData Name NumBits Endianness BasicTy


sizeOfContainer :: Container -> Maybe Int
sizeOfContainer container =
  case container of
    TlmPoint name ty sem ->
      sizeOfBasicTy ty

    Section name children ->
      Pre.sum <$> (sequence $ Pre.map sizeOfContainer children)

    AllOf name children ->
      Pre.maximum <$> (sequence $ Pre.map sizeOfContainer children)

    OneOf _ _ _ EmptyAllowed ->
      Nothing

    OneOf _ _ map EmptyNotAllowed ->
      let maybeSizes = sequence $ Pre.map sizeOfContainer $ M.elems map
       in case maybeSizes of
            Nothing ->
              Nothing
            Just sizes ->
             case L.and $ L.map (== (L.head sizes)) $ sizes of
               True -> Just $ L.head sizes
               False -> Nothing

sizeOfBasic :: BasicTy -> TlmDecoded -> Int
sizeOfBasic ty tlmDecoded =
  case ty of
    TlmPrim  primTy ->
      sizeOfPrim primTy

    TlmChar _ ->
      1

    TlmDbl  _ _ ->
      8

    TlmBits ty _ _ _ ->
      sizeOfPrim ty

    TlmFlt  _ _ ->
      4

    TlmArray (FixedSize n) ty _ ->
      n * sizeOfPrim ty

    TlmArray (VariableSize nam n) ty _ ->
      case M.lookup nam tlmDecoded of
        Nothing ->
          error $ nam ++ " was not found in telemetry packet"

        Just tlm ->
          case tlmPayload tlm of
            TlmPrim prim ->
              (n *) . ((sizeOfPrim ty) *) $ unwrapPrim prim

    TlmBuff (FixedSize n) _ ->
      n

    TlmBuff (VariableSize nam n) _ ->
      case M.lookup nam tlmDecoded of
        Nothing ->
          error $ nam ++ " was not found in telemetry packet"

        Just tlm ->
          case tlmPayload tlm of
            TlmPrim prim ->
              n + unwrapPrim prim

sizeOfBasicTy :: BasicTy -> Maybe Int
sizeOfBasicTy ty =
  case ty of
    TlmPrim  primTy ->
      Just $ sizeOfPrim primTy

    TlmChar _ ->
      Just 1

    TlmDbl  _ _ ->
      Just 8

    TlmBits ty _ _ _ ->
      Just $ sizeOfPrim ty

    TlmFlt  _ _ ->
      Just 4

    TlmArray (FixedSize n) ty _ ->
      Just $ n * sizeOfPrim ty

    TlmArray (VariableSize _ _) ty _ ->
      Nothing

    TlmBuff (FixedSize n) _ ->
      Just n

    TlmBuff (VariableSize nam n) _ ->
        Nothing

sizeOfPrim (Uint8  _)   = 1
sizeOfPrim (Uint16 _ _) = 2
sizeOfPrim (Uint32 _ _) = 4
sizeOfPrim (Uint64 _ _) = 8
sizeOfPrim (Sint8  _)   = 1
sizeOfPrim (Sint16 _ _) = 2
sizeOfPrim (Sint32 _ _) = 4
sizeOfPrim (Sint64 _ _) = 8

endian endianess little big =
  case endianess of
    LittleEndian ->
      little

    BigEndian ->
      big

recommutateTlmPoint :: BasicData -> Put
recommutateTlmPoint tlmData =
  case tlmData of
    TlmPrim prim ->
      recommutatePrim prim

    TlmChar chr ->
      putCharUtf8 chr

    TlmDbl e dbl ->
      endian e putDoublele putDoublebe dbl

    TlmFlt e flt ->
      endian e putFloatle putFloatbe flt

    TlmArray siz prim prims ->
      error $ "recommutating arrays is not yet implemented"

    TlmBuff siz bytes ->
      putByteString bytes

    TlmBits primTy offset numBits prim ->
      -- NOTE bits are not layed down as they must be preceded by a field containing
      -- the full primitive telemtry point. This first field will be layed down by
      -- the recomming of AnyOf
      return ()

recommutatePrim prim =
  case prim of
    Uint8 n ->
      putWord8 n

    Uint16 e  n ->
      endian e putWord16le putWord16le n

    Uint32 e  n ->
      endian e putWord32le putWord32be n

    Uint64 e  n ->
      endian e putWord64le putWord64be n

    Sint8  n ->
      putInt8 n

    Sint16 e  n ->
      endian e putInt16le putInt16be n

    Sint32 e  n ->
      endian e putInt32le putInt32be n

    Sint64 e  n ->
      endian e putInt64le putInt64be n

recommutate :: Container -> TlmDecoded -> Put
recommutate container tlmDecoded =
  case container of
    TlmPoint name basicTy _ ->
      case M.lookup name tlmDecoded of
        Nothing ->
          error $ "Could not find " ++ name ++ " during encoding"

        Just tlmData ->
          recommutateTlmPoint $ tlmPayload tlmData

    Section name children ->
      F.fold $ Pre.map (flip recommutate tlmDecoded) children

    AllOf name children ->
      -- FIXME if this fails, it would be better to try the next child
      recommutate (Pre.head children) tlmDecoded

    OneOf name key choice _ ->
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


calculateChecksum prim checkType bytes =
  let n = (fromIntegral $ B.length bytes) `div` (sizeOfPrim prim)
      vals = runGet (Pre.sequence . Pre.replicate n . getPrim $ prim) $ BL.fromStrict bytes
  in case checkType of
       ChecksumUnderflow -> Pre.foldl1 (-) vals
       ChecksumOverflow -> Pre.foldl1 (+) vals

findTlm name map =
  case M.lookup name map of
    Nothing ->
      error $ "Did not find " ++ name ++ " in decoded telemetry.\n" ++ show map
    Just val ->
      val

-- Note- defaults to BigEndian for 8 bit values
getEndianness :: Prim f -> Endianness
getEndianness prim
  = case prim of
      Uint8 _ -> BigEndian
      Uint16 e _ -> e
      Uint32 e _ -> e
      Uint64 e _ -> e
      Sint8  _ -> BigEndian
      Sint16  e _ -> e
      Sint32  e _ -> e
      Sint64  e _ -> e

unPrim :: BasicData -> PrimData
unPrim (TlmPrim prim) = prim
unPrim basicTlm = error $ "Required a primitive type, got '" ++ show basicTlm ++ "'"

getBuffer :: BasicData -> ByteString
getBuffer (TlmBuff siz bytes) = bytes
getBuffer basicTlm = error $ "Required a buffer type, got '" ++ show basicTlm ++ "'"

handleSemantic :: Name -> BasicData -> TlmDecoded -> Semantic -> Maybe TlmValidationError
handleSemantic checkName tlmData tlmDecoded semantic =
  case semantic of
    SemanticChecksum bufferName checkType ->
      let bytes = getBuffer $ tlmPayload (findTlm bufferName tlmDecoded)
          actual = calculateChecksum expected checkType bytes
          expected = unPrim tlmData
      in case actual == expected of
           True -> Nothing
           False -> Just $ TlmValidationChecksumError checkName actual expected bytes

    SemanticRequired requiredValue ->
      let actual = unPrim tlmData
      in case actual == requiredValue of
           True ->
             Nothing

           False ->
             Just $ TlmValidationValueError checkName requiredValue actual

    otherwise ->
       Nothing

decomOrError :: Container -> Get TlmDecoded
decomOrError tlmDef =
  eitherT (error . show) (return) $ decommutate tlmDef

decommutate :: Container -> Decom TlmDecoded
decommutate tlmDef =
   fst <$> decommutate' tlmDef (M.empty, 0)

decommutate' :: Container -> (TlmDecoded, Int) -> Decom (TlmDecoded, Int)
decommutate' tlmDef (tlmDecoded, offset) =
  case tlmDef of
    TlmPoint name ty maybeSemantic -> do
      tlmData <- lift $ getBasic tlmDecoded ty
      let size = sizeOfBasic ty tlmDecoded
      let success = (M.insert name (Tlm name offset tlmData) tlmDecoded, offset + size)
      case maybeSemantic of
        Nothing -> 
          return success

        Just semantic ->
          case handleSemantic name tlmData tlmDecoded semantic of
           Nothing ->
            return success

           Just e -> failedDecom e

    Section name children ->
      M.foldM (flip decommutate') (tlmDecoded, offset) children

    AllOf name children ->
      let decom (tlmDecoded', offsets) tlmDef' =
            do
              (tlmDecoded'', offset') <- EitherT $ lookAhead $ runEitherT $ decommutate' tlmDef' (tlmDecoded', offset)
              return $ (tlmDecoded'', offset' : offsets)
       in do
           (tlmDecoded', offsets) <- M.foldM decom (tlmDecoded, []) children
           let maxOffset = Pre.maximum offsets
           lift $ Data.Binary.Get.skip $ maxOffset - offset
           return (tlmDecoded', maxOffset)

    OneOf name key map emptyAllowed ->
      case M.lookup key tlmDecoded of
        Nothing ->
          case emptyAllowed of
            EmptyAllowed ->
              return (tlmDecoded, offset)

            EmptyNotAllowed ->
              error $ "key not found in telemetry packet"

        Just (Tlm _ _ (TlmPrim prim)) ->
          case M.lookup (unwrapPrim prim) map of
            Nothing ->
              error $ "Value of " ++ key ++ ", " ++ Pre.show prim ++ ", not found"

            Just tlmDef' ->
              decommutate' tlmDef' (tlmDecoded, offset)

getPrim :: Prim f -> Get PrimData
getPrim ty =
  case ty of
    Uint8 _ ->
      (Uint8) <$> getWord8

    Uint16 e _ ->
      (Uint16 e) <$> endian e getWord16le getWord16be

    Uint32 e _ ->
      (Uint32 e) <$> endian e getWord32le getWord32be

    Uint64 e _ ->
      (Uint64 e)  <$> endian e getWord64le getWord64be

    Sint8 _ ->
      (Sint8) <$> getInt8

    Sint16 e _ ->
      (Sint16 e) <$> endian e getInt16le getInt16be

    Sint32  e _ ->
      (Sint32 e) <$> endian e getInt32le getInt32be

    Sint64 e _ ->
      (Sint64 e) <$> endian e getInt64le getInt64be

getBasic :: TlmDecoded -> BasicTy -> Get BasicData
getBasic tlmDecoded ty =
  case ty of
    TlmChar _ ->
      (TlmChar . toEnum . fromEnum) <$> getWord8

    TlmBits tyWithin offset numBits ty ->
      (TlmPrim . extractBits offset numBits ty) <$>
                    (getPrim tyWithin)

    TlmDbl e _ ->
      (TlmDbl e) <$> endian e getDoublele getDoublebe

    TlmFlt e _ ->
      (TlmFlt e) <$> endian e getFloatle getFloatbe

    TlmArray (FixedSize siz) ty _ ->
      (TlmArray (FixedSize siz) ty) <$>
         (Pre.sequence . Pre.replicate siz $ (getPrim ty))

    TlmBuff (FixedSize siz) _ ->
      (TlmBuff (FixedSize siz)) <$> getByteString siz

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

