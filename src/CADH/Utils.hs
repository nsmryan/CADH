module CADH.Utils where

import Data.Binary.Get as BGet
import Data.Binary.Put as BPut
import Data.Binary.Bits as Bi
import Data.Binary.Bits.Get as BiGet
import Data.Binary.Bits.Put as BiPut

import Data.Word
import Data.Bits

{- Utilities -}
putBitsEnum bitsNeeded n = BiPut.putWord8 bitsNeeded . mask n . fromIntegral . fromEnum
getBitsEnum bitsNeeded n = (toEnum . fromIntegral . mask n) <$> BiGet.getWord8 bitsNeeded

mask n m = makeMask n .&. m

-- | copied from Data.Binary.Bits.Get
-- | make_mask 3 = 00000111
makeMask :: (Bits a, Num a) => Int -> a
makeMask n = (1 `shiftL` fromIntegral n) - 1
{-# SPECIALIZE makeMask :: Int -> Int    #-}
{-# SPECIALIZE makeMask :: Int -> Word   #-}
{-# SPECIALIZE makeMask :: Int -> Word8  #-}
{-# SPECIALIZE makeMask :: Int -> Word16 #-}
{-# SPECIALIZE makeMask :: Int -> Word32 #-}
{-# SPECIALIZE makeMask :: Int -> Word64 #-}
