{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
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
  TlmDecoded,
  PacketDef(..),
  containerCSVHeader,
  decommutate,
  recommutate,
  recommutateTlmPoint,
  recommutatePrim,
  printTlmPoint,
  Name,
  Size(..),
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
  bitField,
  sint64Tlmbe,
  sizeOfBasic
) where

import Prelude as Pre

import Control.Monad.Identity
import Control.Monad as M

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
import Data.Word
import Data.Proxy
import Data.Binary
import Data.Binary.Put
import Data.Binary.Get
import Data.Int

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

data Size
  = FixedSize Int
  | VariableSize Name Int
  deriving (Show, Eq, Ord)

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
  | SemanticExpected a
  | SemanticLength Int
  deriving (Show, Eq)

data Endianness
  = BigEndian
  | LittleEndian
  deriving (Show, Eq, Enum, Ord)

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

deriving instance
  (Ord (f Word8), Ord (f Word16), Ord (f Word32), Ord (f Word64),
   Ord (f Int8), Ord (f Int16), Ord (f Int32), Ord (f Int64)) =>
  Ord (Prim f)

type PrimTy   = Prim TlmTy
type PrimData = Prim Identity

data BasicTlm f
  = TlmPrim   (Prim f)
  | TlmChar   (f Char)
  | TlmDbl    Endianness (f Double)
  | TlmFlt    Endianness (f Float)
  | TlmArray  Size  (Prim Proxy) [Prim f]
  | TlmBuff   Size (f ByteString)
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


data Container = TlmPoint Name BasicTy
               | Section Name [Container]
               | AllOf Name [Container]
               | OneOf Name Name (M.Map Int Container)
               deriving (Show, Eq)

data Tlm a = Tlm 
  { tlmName    :: Name
  , tlmOffset  :: Offset 
  , tlmPayload :: a
  } deriving (Show, Eq)

data PacketDef
  = PacketDef { packetName :: Name
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

        TlmChar (Identity chr) ->
          char8 chr

        TlmDbl    e (Identity dbl) ->
          doubleDec dbl

        TlmFlt    e (Identity flt) ->
          floatDec flt

        TlmArray size prim prims ->
          byteString $ F.fold $ L.intersperse (BChar.singleton ' ') $ Pre.map Csv.toField prims 

        TlmBuff size (Identity bytes) ->
          byteStringHex bytes

        TlmBits primty offset numBits prim ->
          byteString $ Csv.toField prim

instance Csv.ToField PrimData where
  toField primData =
    BL.toStrict $ toLazyByteString $ 
      case primData of
        Uint8    (Identity n) ->
          word8Dec n

        Uint16 e (Identity n) ->
          word16Dec n

        Uint32 e (Identity n) ->
          word32Dec n

        Uint64 e (Identity n) ->
          word64Dec n

        Sint8    (Identity n) ->
          int8Dec n

        Sint16 e (Identity n) ->
          int16Dec n

        Sint32 e (Identity n) ->
          int32Dec n

        Sint64 e (Identity n) ->
          int64Dec n

containerCSVHeader :: Container -> Csv.Header
containerCSVHeader container = V.fromList $ Pre.map BChar.pack $ containerCSVHeader' container

containerCSVHeader' :: Container -> [String]
containerCSVHeader' container = 
  case container of
    TlmPoint name ty ->
      [name]

    Section name children ->
      Pre.concatMap containerCSVHeader' children

    AllOf name children ->
      Pre.concatMap containerCSVHeader' children

    OneOf name key map ->
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

type TlmDecoded = M.Map Name TlmData

{- Convience functions -}
container nam children = Section nam children
arrTlm nam sz ty = TlmPoint nam (TlmArray (FixedSize sz) ty [])
arrTlmVariable nam szName ty = TlmPoint nam (TlmArray (VariableSize szName 0) ty [])

doubleTlm   nam endianness  = TlmPoint nam (TlmDbl endianness TlmAny)
doubleTlmle nam             = doubleTlm nam LittleEndian
doubleTlmbe nam             = doubleTlm nam BigEndian
floatTlm    nam  endianness = TlmPoint nam (TlmFlt endianness TlmAny)
floatTlmle  nam             = floatTlm nam LittleEndian
floatTlmbe  nam             = floatTlm nam BigEndian

uint8Tlm nam = TlmPoint nam (TlmPrim (Uint8 TlmAny))
sint8Tlm nam = TlmPoint nam (TlmPrim (Sint8 TlmAny))

uint16Tlm endianness nam = TlmPoint nam (TlmPrim (Uint16 endianness TlmAny))
sint16Tlm endianness nam = TlmPoint nam (TlmPrim (Sint16 endianness TlmAny))
uint16Tlmle = uint16Tlm LittleEndian
uint16Tlmbe = uint16Tlm BigEndian
sint16Tlmle = sint16Tlm LittleEndian
sint16Tlmbe = sint16Tlm BigEndian

uint32Tlm endianness nam = TlmPoint nam (TlmPrim (Uint32 endianness TlmAny))
sint32Tlm endianness nam = TlmPoint nam (TlmPrim (Sint32 endianness TlmAny))
uint32Tlmle = uint32Tlm LittleEndian
uint32Tlmbe = uint32Tlm BigEndian
sint32Tlmle = sint32Tlm LittleEndian
sint32Tlmbe = sint32Tlm BigEndian

uint64Tlm endianness nam = TlmPoint nam (TlmPrim (Uint64 endianness TlmAny))
sint64Tlm endianness nam = TlmPoint nam (TlmPrim (Sint64 endianness TlmAny))
uint64Tlmle = uint64Tlm LittleEndian
uint64Tlmbe = uint64Tlm BigEndian
sint64Tlmle = sint64Tlm LittleEndian
sint64Tlmbe = sint64Tlm BigEndian


bitField name withinType bitTlmPoints
  = AllOf (name ++ "Group") $ (TlmPoint (name ++ "Field") (TlmPrim withinType)) : bitTlmPoints

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

sizeOfPrim (Uint8  _)   = 1
sizeOfPrim (Uint16 _ _) = 2
sizeOfPrim (Uint32 _ _) = 4
sizeOfPrim (Uint64 _ _) = 8
sizeOfPrim (Sint8  _)   = 1
sizeOfPrim (Sint16 _ _) = 2
sizeOfPrim (Sint32 _ _) = 4
sizeOfPrim (Sint64 _ _) = 8

recommutateTlmPoint :: BasicData -> Put
recommutateTlmPoint tlmData = 
  case tlmData of
    TlmPrim prim ->
      recommutatePrim prim

    TlmChar (Identity chr) ->
      putCharUtf8 chr

    TlmDbl e (Identity dbl) ->
      case e of
        BigEndian -> 
          putDoublebe dbl
        LittleEndian -> 
          putDoublele dbl

    TlmFlt e (Identity flt) ->
      case e of
        BigEndian -> 
          putFloatbe flt
        LittleEndian -> 
          putFloatle flt

    TlmArray siz prim prims ->
      undefined

    TlmBuff siz bytes ->
      putByteString $ runIdentity bytes

    TlmBits primTy offset numBits prim ->
      -- NOTE bits are not layed down as they must be preceded by a field containing
      -- the full primitive telemtry point. This first field will be layed down by
      -- the recomming of AnyOf
      return ()

recommutatePrim prim = 
  case prim of
    Uint8 (Identity n) ->
      putWord8 n

    Uint16 e (Identity n) ->
      case e of
        BigEndian ->
          putWord16be n
        LittleEndian ->
          putWord16le n

    Uint32 e (Identity n) ->
      case e of
        BigEndian ->
          putWord32be n
        LittleEndian ->
          putWord32le n

    Uint64 e (Identity n) ->
      case e of
        BigEndian ->
          putWord64be n
        LittleEndian ->
          putWord64le n

    Sint8 (Identity n) ->
      putInt8 n

    Sint16 e (Identity n) ->
      case e of
        BigEndian ->
          putInt16be n
        LittleEndian ->
          putInt16le n

    Sint32 e (Identity n) ->
      case e of
        BigEndian ->
          putInt32be n
        LittleEndian ->
          putInt32le n

    Sint64 e (Identity n) ->
      case e of
        BigEndian ->
          putInt64be n
        LittleEndian ->
          putInt64le n

recommutate :: Container -> TlmDecoded -> Put
recommutate container tlmDecoded =
  case container of
    TlmPoint name basicTy -> 
      case M.lookup name tlmDecoded of
        Nothing ->
          error $ "Could not find " ++ name ++ " during encoding"

        Just tlmData ->
          recommutateTlmPoint $ tlmPayload tlmData

    Section name children -> 
      F.fold $ Pre.map (flip recommutate tlmDecoded) children 

    AllOf name children -> 
      -- FIXME if this failures, it would be better to try the next child
      recommutate (Pre.head children) tlmDecoded 

    OneOf name key choice -> 
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


decommutate :: Container -> Get TlmDecoded
decommutate tlmDef = fst <$> decommutate' tlmDef M.empty 0

decommutate' :: Container -> TlmDecoded -> Int -> Get (TlmDecoded, Int)
decommutate' tlmDef tlmDecoded offset =
  case tlmDef of
    TlmPoint name ty ->
      do tlmData <- getBasic tlmDecoded ty
         let offset' = sizeOfBasic ty tlmDecoded
         return $ (M.insert name (Tlm name offset tlmData) tlmDecoded, offset + offset')

    Section name children ->
      let decom (tlmDecoded', offset') tlmDef' = decommutate' tlmDef' tlmDecoded' offset'
      in M.foldM decom (tlmDecoded, offset) children

    AllOf name children ->
      let decom (tlmDecoded', offsets) tlmDef' = 
            do (tlmDecoded'', offset') <- lookAhead $ decommutate' tlmDef' tlmDecoded' offset
               return (tlmDecoded'', offset' : offsets)
       in do (tlmDecoded', offsets) <- M.foldM decom (tlmDecoded, []) children
             let offset' = Pre.maximum offsets
             Data.Binary.Get.skip $ offset' - offset
             return (tlmDecoded', offset')

    OneOf name key map ->
      case M.lookup key tlmDecoded of
        Nothing -> error $ "key not found in telemetry packet"
        Just (Tlm _ _ (TlmPrim prim)) ->
          case M.lookup (unwrapPrim prim) map of
            Nothing ->
              error $ "Value of " ++ key ++ ", " ++ Pre.show prim ++ ", not found"
            Just tlmDef' ->
              decommutate' tlmDef' tlmDecoded offset

getPrim :: Prim f -> Get PrimData
getPrim ty = 
  case ty of
    Uint8 _ ->
      (Uint8 . Identity) <$> getWord8

    Uint16 e _ ->
      (Uint16 e . Identity) <$>
        (case e of
           BigEndian    -> getWord16be
           LittleEndian -> getWord16le)

    Uint32 e _ ->
      (Uint32 e . Identity) <$>
         (case e of
            BigEndian    -> getWord32be
            LittleEndian -> getWord32le)

    Uint64 e _ ->
      (Uint64 e . Identity)  <$>
         (case e of
            BigEndian    -> getWord64be
            LittleEndian -> getWord64le)

    Sint8 _ ->
      (Sint8 . Identity) <$> getInt8

    Sint16 e _ ->
      (Sint16 e . Identity) <$>
         (case e of
            BigEndian    -> getInt16be
            LittleEndian -> getInt16le)

    Sint32  e _ ->
      (Sint32 e . Identity) <$>
         (case e of
            BigEndian    -> getInt32be
            LittleEndian -> getInt32le)

    Sint64 e _ ->
      (Sint64 e . Identity) <$>
         (case e of
            BigEndian    -> getInt64be
            LittleEndian -> getInt64le)

getBasic :: TlmDecoded -> BasicTy -> Get BasicData
getBasic tlmDecoded ty = 
  case ty of
    TlmChar _ ->
      (TlmChar . Identity . toEnum . fromEnum) <$> getWord8

    TlmBits tyWithin offset numBits ty ->
      (TlmPrim . extractBits offset numBits ty) <$>
                    (getPrim tyWithin)

    TlmDbl e _ ->
      (TlmDbl e . Identity) <$>
         (case e of
            BigEndian    -> getDoublebe
            LittleEndian -> getDoublele)

    TlmFlt e _ ->
      (TlmFlt e . Identity) <$>
         (case e of
            BigEndian    -> getFloatbe
            LittleEndian -> getFloatle)

    TlmArray (FixedSize siz) ty _ ->
      (TlmArray (FixedSize siz) ty) <$>
         (Pre.sequence . Pre.replicate siz $ (getPrim ty))

    TlmBuff (FixedSize siz) _ ->
      (TlmBuff (FixedSize siz) . Identity) <$> getByteString siz

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
